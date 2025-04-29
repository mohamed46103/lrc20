use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    str::FromStr,
};

use bitcoin::{
    Amount, OutPoint as BitcoinOutPoint, PrivateKey, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    consensus::Decodable,
    key::XOnlyPublicKey,
    locktime::absolute::LockTime,
    psbt::{self, Output},
    secp256k1::{self, All, PublicKey, Secp256k1},
    transaction::Version,
};
use eyre::{OptionExt, ensure};

use bdk::miniscript::ToPublicKey;
use bdk::{
    SignOptions,
    bitcoincore_rpc::RawTx,
    descriptor,
    miniscript::{Descriptor, DescriptorPublicKey, psbt::PsbtInputExt},
    signer::{SignerContext, SignerWrapper},
};
use lrc20_receipts::{
    EmptyReceiptProof, Receipt, ReceiptKey, ReceiptProof as Lrc20ReceiptProof, SigReceiptProof,
    TaprootProof, TokenAmount, TokenPubkey,
};
use lrc20_types::{
    Announcement, AnyAnnouncement,
    announcements::{
        IssueAnnouncement, TokenPubkeyAnnouncement, TransferOwnershipAnnouncement,
        TxFreezeAnnouncement,
    },
};
use lrc20_types::{Lrc20Transaction, Lrc20TxType, ProofMap};
use pyo3::{exceptions::PyRuntimeError, pyclass, pymethods};

use crate::txsigner::{TransactionSigner, sign_input};

#[pyclass]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    txid: Txid,
    vout: u32,
}

#[pymethods]
impl OutPoint {
    #[new]
    pub fn new(txid: String, vout: u32) -> eyre::Result<Self> {
        Ok(Self {
            txid: Txid::from_str(&txid)?,
            vout,
        })
    }
}

impl From<OutPoint> for BitcoinOutPoint {
    fn from(value: OutPoint) -> Self {
        Self::new(value.txid, value.vout)
    }
}

impl From<BitcoinOutPoint> for OutPoint {
    fn from(value: BitcoinOutPoint) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyLrc20Transaction(pub Lrc20Transaction);

impl From<Lrc20Transaction> for PyLrc20Transaction {
    fn from(tx: Lrc20Transaction) -> Self {
        Self(tx)
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct ReceiptProof {
    token_amount: u128,
    token_pubkey: String,
    inner_key: String,
}

#[pymethods]
impl ReceiptProof {
    #[new]
    pub fn new(token_amount: u128, token_pubkey: String, inner_key: String) -> Self {
        Self {
            token_amount,
            token_pubkey,
            inner_key,
        }
    }
}

impl ReceiptProof {
    pub fn receipt(&self) -> eyre::Result<Receipt> {
        let xonly_pubkey = XOnlyPublicKey::from_str(&self.token_pubkey)?;
        let token_pubkey = TokenPubkey::from(xonly_pubkey);
        Ok(Receipt::new(
            TokenAmount::from(self.token_amount),
            token_pubkey,
        ))
    }
}

impl TryFrom<ReceiptProof> for Lrc20ReceiptProof {
    type Error = eyre::Error;

    fn try_from(value: ReceiptProof) -> Result<Self, Self::Error> {
        let pubkey = PublicKey::from_str(&value.inner_key)?;
        let token_pubkey = TokenPubkey::from(pubkey);
        let receipt = Receipt::new(TokenAmount::from(value.token_amount), token_pubkey);

        Ok(Lrc20ReceiptProof::Sig(SigReceiptProof::new(
            receipt, pubkey, None,
        )))
    }
}

#[allow(clippy::large_enum_variant)]
#[pyclass]
#[derive(Clone)]
pub enum BuilderInput {
    Receipt {
        outpoint: OutPoint,
        proof: ReceiptProof,
        prev_tx_hash: String,
    },
    TaprootReceipt {
        outpoint: OutPoint,
        proof: ReceiptProof,
        prev_tx_hash: String,
    },
    TweakedSatoshis {
        outpoint: OutPoint,
        prev_tx_hash: String,
    },
    Satoshis {
        outpoint: OutPoint,
        prev_tx_hash: String,
    },
}

impl BuilderInput {
    fn outpoint(&self) -> OutPoint {
        match self {
            BuilderInput::Receipt { outpoint, .. }
            | BuilderInput::TaprootReceipt { outpoint, .. }
            | BuilderInput::TweakedSatoshis { outpoint, .. }
            | BuilderInput::Satoshis { outpoint, .. } => *outpoint,
        }
    }

    fn prev_tx(&self) -> eyre::Result<Transaction> {
        match self {
            BuilderInput::Receipt { prev_tx_hash, .. }
            | BuilderInput::TaprootReceipt { prev_tx_hash, .. }
            | BuilderInput::TweakedSatoshis { prev_tx_hash, .. }
            | BuilderInput::Satoshis { prev_tx_hash, .. } => {
                let prev_tx_bytes = hex::decode(prev_tx_hash)?;
                let mut readed = Cursor::new(prev_tx_bytes);
                let tx = Transaction::consensus_decode(&mut readed)?;
                Ok(tx)
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum BuilderOutput {
    Receipt {
        token_pubkey: TokenPubkey,
        satoshis: u64,
        amount: u128,
        recipient: secp256k1::PublicKey,
    },
    TaprootReceipt {
        token_pubkey: TokenPubkey,
        satoshis: u64,
        amount: u128,
        recipient: PublicKey,
    },
}

struct TransactionBuilder {
    /// Defines if the transactions is issuance or not.
    ///
    /// By that [`TransactionBuilder`] will consider to whether add or not the
    /// inputs with LRC20 coins to satisfy consideration rules.
    is_issuance: bool,

    /// Value of satoshis that will be attached to change output.
    change_satoshis: u64,

    private_key: PrivateKey,

    /// Storage of outputs which will be formed into transaction outputs and
    /// proofs.
    outputs: Vec<BuilderOutput>,

    /// Storage of inputs which will be formed into transaction inputs and
    /// proofs.
    inputs: HashMap<OutPoint, BuilderInput>,

    /// Transaction Signer is responsible for signing the transaction.
    tx_signer: TransactionSigner,
}

#[pyclass]
pub struct AnnouncementTransactionBuilder(TransactionBuilder);

#[pymethods]
impl AnnouncementTransactionBuilder {
    #[new]
    pub fn new(private_key: String) -> eyre::Result<Self> {
        let private_key = PrivateKey::from_wif(&private_key)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self(
            TransactionBuilder::new(false, private_key)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    pub fn add_input(&mut self, input: BuilderInput) -> eyre::Result<()> {
        ensure!(
            matches!(input, BuilderInput::Satoshis { .. }),
            "Announcement TXs only accept satoshi inputs"
        );

        self.0.add_input(input);
        Ok(())
    }

    pub fn set_change_satoshis(&mut self, change: u64) {
        self.0.set_change_satoshis(change);
    }

    pub async fn freeze(
        &mut self,
        token_pubkey_str: String,
        outpoint: OutPoint,
    ) -> eyre::Result<PyLrc20Transaction> {
        let token_pubkey_xonly_pubkey = XOnlyPublicKey::from_str(&token_pubkey_str)?;
        let token_pubkey = TokenPubkey::from(token_pubkey_xonly_pubkey);
        let tx_freeze = TxFreezeAnnouncement::new(token_pubkey, BitcoinOutPoint::from(outpoint));

        let lrc20_tx = self
            .0
            .create_announcement_tx(tx_freeze.into())
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyLrc20Transaction(lrc20_tx))
    }

    pub async fn transfer_ownership(
        &mut self,
        token_pubkey_str: String,
        new_owner: String,
    ) -> eyre::Result<PyLrc20Transaction> {
        let token_pubkey_xonly_pubkey = XOnlyPublicKey::from_str(&token_pubkey_str)?;
        let token_pubkey = TokenPubkey::from(token_pubkey_xonly_pubkey);
        let new_owner_script = ScriptBuf::from_hex(&new_owner)?;
        let transfer_ownership_announcement =
            TransferOwnershipAnnouncement::new(token_pubkey, new_owner_script);

        let lrc20_tx = self
            .0
            .create_announcement_tx(transfer_ownership_announcement.into())
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyLrc20Transaction(lrc20_tx))
    }

    pub async fn token_pubkey(
        &mut self,
        token_pubkey_str: String,
        name: String,
        symbol: String,
        decimal: u8,
        max_supply: u128,
        is_freezable: bool,
    ) -> eyre::Result<PyLrc20Transaction> {
        let token_pubkey_xonly_pubkey = XOnlyPublicKey::from_str(&token_pubkey_str)?;
        let token_pubkey = TokenPubkey::from(token_pubkey_xonly_pubkey);
        let token_pubkey_announcement = TokenPubkeyAnnouncement::new(
            token_pubkey,
            name,
            symbol,
            decimal,
            max_supply,
            is_freezable,
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let lrc20_tx = self
            .0
            .create_announcement_tx(token_pubkey_announcement.into())
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyLrc20Transaction(lrc20_tx))
    }
}

#[pyclass]
pub struct SweepTransactionBuilder(TransactionBuilder);

#[pymethods]
impl SweepTransactionBuilder {
    #[new]
    pub fn new(private_key: String) -> eyre::Result<Self> {
        let private_key = PrivateKey::from_wif(&private_key)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self(
            TransactionBuilder::new(true, private_key)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    pub fn add_input(&mut self, input: BuilderInput) -> eyre::Result<()> {
        ensure!(
            matches!(input, BuilderInput::TweakedSatoshis { .. }),
            "Sweep TXs only accept tweaked satoshi inputs"
        );

        self.0.add_input(input);
        Ok(())
    }

    pub async fn sweep(&mut self, fee_rate_vb: f64) -> eyre::Result<String> {
        let sweep_tx = self.0.build_sweep(fee_rate_vb).await?;
        Ok(sweep_tx.raw_hex())
    }
}

#[pyclass]
pub struct IssuanceTransactionBuilder(TransactionBuilder);

#[pymethods]
impl IssuanceTransactionBuilder {
    #[new]
    pub fn new(private_key: String) -> eyre::Result<Self> {
        let private_key = PrivateKey::from_wif(&private_key)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self(
            TransactionBuilder::new(true, private_key)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    pub fn add_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        self.0
            .add_recipient(token_pubkey, recipient, amount, satoshis)
    }

    pub fn add_taproot_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        self.0
            .add_taproot_recipient(token_pubkey, recipient, amount, satoshis)
    }

    pub fn add_input(&mut self, input: BuilderInput) {
        self.0.add_input(input);
    }

    pub fn set_change_satoshis(&mut self, change: u64) {
        self.0.set_change_satoshis(change);
    }

    pub async fn finish(&mut self) -> eyre::Result<PyLrc20Transaction> {
        self.0.finish().await
    }
}

#[pyclass]
pub struct TransferTransactionBuilder(TransactionBuilder);

#[pymethods]
impl TransferTransactionBuilder {
    #[new]
    pub fn new(private_key: String) -> eyre::Result<Self> {
        let private_key = PrivateKey::from_wif(&private_key)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self(TransactionBuilder::new(false, private_key)?))
    }

    /// Add recipient to the transaction.
    pub fn add_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        self.0
            .add_recipient(token_pubkey, recipient, amount, satoshis)
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        self.0
            .add_taproot_recipient(token_pubkey, recipient, amount, satoshis)
    }

    pub fn set_change_satoshis(&mut self, change: u64) {
        self.0.set_change_satoshis(change);
    }

    /// Add input to the transaction.
    pub fn add_input(&mut self, input: BuilderInput) {
        self.0.add_input(input);
    }

    /// Finish transfer building, and create Bitcoin transactions with attached
    /// proofs for it in [`Lrc20Transaction`].
    pub async fn finish(&mut self) -> eyre::Result<PyLrc20Transaction> {
        self.0.finish().await
    }
}

impl TransactionBuilder {
    fn new(is_issuance: bool, private_key: PrivateKey) -> eyre::Result<Self> {
        let ctx = Secp256k1::new();

        Ok(Self {
            is_issuance,
            change_satoshis: 0,
            private_key,
            outputs: Vec::new(),
            inputs: HashMap::new(),
            tx_signer: TransactionSigner::new(ctx, private_key),
        })
    }

    /// Add recipient for Sig receipt proof
    pub fn add_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        let recipient = PublicKey::from_str(&recipient)?;
        let xonly_pubkey = XOnlyPublicKey::from_str(&token_pubkey)?;
        let token_pubkey = TokenPubkey::from(xonly_pubkey);

        self.outputs.push(BuilderOutput::Receipt {
            token_pubkey,
            satoshis,
            amount,
            recipient,
        });

        Ok(())
    }

    /// Add recipient for P2TR receipt proof
    pub fn add_taproot_recipient(
        &mut self,
        token_pubkey: String,
        recipient: String,
        amount: u128,
        satoshis: u64,
    ) -> eyre::Result<()> {
        let token_pubkey = TokenPubkey::from_str(&token_pubkey)?;
        let recipient = PublicKey::from_str(&recipient)?;

        self.outputs.push(BuilderOutput::TaprootReceipt {
            token_pubkey,
            satoshis,
            amount,
            recipient,
        });

        Ok(())
    }

    /// Add receipt input to the transaction with given outpoint.
    fn add_input(&mut self, input: BuilderInput) -> &mut Self {
        self.inputs.insert(input.outpoint(), input);
        self
    }

    fn set_change_satoshis(&mut self, change: u64) -> &mut Self {
        self.change_satoshis = change;
        self
    }

    async fn finish(&mut self) -> eyre::Result<PyLrc20Transaction> {
        self.build_tx().await
    }

    /// Inserts empty receipt proofs to the outputs that don't hold any Receipt data,
    /// i.e. to the Satoshis only outputs.
    ///
    /// The output `script_pubkey` is also tweaked with an empty receipt, so the method
    /// creates wrapped satoshis that can be spent after sweeping them to a p2wpkh address.
    fn insert_empty_receiptproofs(
        &self,
        output_proofs: &mut Vec<Lrc20ReceiptProof>,
        tx_outs: &mut [TxOut],
    ) -> eyre::Result<()> {
        let ctx = Secp256k1::new();

        // If the tx is an issuance, the first output is `OP_RETURN`, so the offset should be increased.
        let offset = if self.is_issuance {
            output_proofs.len() + 1
        } else {
            output_proofs.len()
        };

        tx_outs.iter_mut().skip(offset).for_each(|tx_out| {
            let (receipt_proof, script_pubkey) =
                get_empty_receipt_proof(self.private_key.public_key(&ctx).inner)
                    .expect("Failed to get empty receiptproof");

            output_proofs.push(receipt_proof);
            tx_out.script_pubkey = script_pubkey;
        });

        Ok(())
    }

    /// Create LRC20 [`Announcement`] transaction for given [`Announcement`].
    pub async fn create_announcement_tx(
        &mut self,
        announcement: Announcement,
    ) -> eyre::Result<Lrc20Transaction> {
        let ctx = Secp256k1::new();

        let spend_tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut psbt = psbt::Psbt {
            unsigned_tx: spend_tx,
            unknown: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            xpub: BTreeMap::new(),
            version: 0,
            inputs: vec![],
            outputs: vec![],
        };

        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: announcement.to_script(),
        });
        psbt.outputs.push(Output::default());

        if self.change_satoshis != 0 {
            let pubkey = &self.private_key.public_key(&ctx);
            let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(self.change_satoshis),
                script_pubkey,
            });
            psbt.outputs.push(Output::default());
        }

        let mut inputs = Vec::new();
        self.process_inputs(&ctx, &mut inputs).await?;

        let mut inputs_to_sign = Vec::new();
        for (i, (outpoint, psbt_input, _weight)) in inputs.into_iter().enumerate() {
            psbt.unsigned_tx.input.push(TxIn {
                previous_output: BitcoinOutPoint::from(outpoint),
                ..Default::default()
            });
            psbt.inputs.push(psbt_input);

            if matches!(
                self.inputs.get(&outpoint).unwrap(),
                BuilderInput::Satoshis { .. }
            ) {
                inputs_to_sign.push(i);
            }
        }

        let signer = SignerWrapper::new(self.private_key, SignerContext::Segwitv0);
        let pubkey = &self.private_key.public_key(&ctx);

        for input_index in inputs_to_sign {
            sign_input(
                &signer,
                &mut psbt,
                input_index,
                &SignOptions::default(),
                &ctx,
                pubkey,
            )?;
        }

        let tx = psbt.extract_tx()?;

        Ok(Lrc20Transaction::new(tx, announcement.into()))
    }

    async fn build_tx(&mut self) -> eyre::Result<PyLrc20Transaction> {
        let ctx = Secp256k1::new();

        // Gather output `script_pubkeys` with satoshis and profos for BDK wallet.
        let mut output_proofs = Vec::new();
        let mut outputs = Vec::new();

        for output in &self.outputs {
            self.process_output(output, &mut output_proofs, &mut outputs)?;
        }

        let mut inputs = Vec::new();
        self.process_inputs(&ctx, &mut inputs).await?;

        let spend_tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut psbt = psbt::Psbt {
            unsigned_tx: spend_tx,
            unknown: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            xpub: BTreeMap::new(),
            version: 0,
            inputs: vec![],
            outputs: vec![],
        };

        if self.is_issuance {
            let announcement = form_issue_announcement(output_proofs.clone())?;

            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: announcement.to_script(),
            });
            psbt.outputs.push(Output::default());
        }

        for (script_pubkey, value) in outputs {
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script_pubkey.clone(),
            });
            psbt.outputs.push(Output::default());
        }

        let pubkey = &self.private_key.public_key(&ctx);
        if self.change_satoshis != 0 {
            let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(self.change_satoshis),
                script_pubkey,
            });
            psbt.outputs.push(Output::default());
        }

        let mut inputs_to_sign = Vec::new();
        for (i, (outpoint, psbt_input, _weight)) in inputs.into_iter().enumerate() {
            psbt.unsigned_tx.input.push(TxIn {
                previous_output: BitcoinOutPoint::from(outpoint),
                ..Default::default()
            });
            psbt.inputs.push(psbt_input);

            if matches!(
                self.inputs.get(&outpoint).unwrap(),
                BuilderInput::Satoshis { .. }
            ) {
                inputs_to_sign.push(i);
            }
        }

        self.insert_empty_receiptproofs(&mut output_proofs, &mut psbt.unsigned_tx.output)?;
        let mut signer_ctx_type = SignerContext::Segwitv0;
        let input_proofs = self
            .inputs
            .values()
            .filter_map(|input| match input {
                BuilderInput::Receipt {
                    outpoint, proof, ..
                } => Some((
                    *outpoint,
                    Lrc20ReceiptProof::try_from(proof.clone()).unwrap(),
                )),
                BuilderInput::TweakedSatoshis { outpoint, .. } => Some((
                    *outpoint,
                    Lrc20ReceiptProof::EmptyReceipt(EmptyReceiptProof::new(
                        self.private_key.public_key(&ctx).inner,
                    )),
                )),
                BuilderInput::Satoshis { .. } => None,
                BuilderInput::TaprootReceipt {
                    proof, outpoint, ..
                } => {
                    let taproot_proof = TaprootProof::new(
                        proof.receipt().ok()?,
                        PublicKey::from_str(&proof.inner_key).ok()?,
                        None,
                    );
                    signer_ctx_type = SignerContext::Tap {
                        is_internal_key: true,
                    };
                    Some((*outpoint, Lrc20ReceiptProof::P2TR(taproot_proof)))
                }
            })
            .collect::<HashMap<OutPoint, Lrc20ReceiptProof>>();

        let signer = SignerWrapper::new(self.private_key, signer_ctx_type);

        let sign_options = SignOptions {
            try_finalize: false,
            trust_witness_utxo: true,
            ..Default::default()
        };
        for input_index in inputs_to_sign {
            sign_input(&signer, &mut psbt, input_index, &sign_options, &ctx, pubkey)?;
        }

        let tx_type = form_tx_type(
            &psbt.unsigned_tx,
            &input_proofs,
            &output_proofs,
            self.is_issuance,
        )?;

        // We need to sign inputs in case of transfer transaction as there are always LRC20 inputs.
        // We also need to sign issue transaction inputs if it spends tweaked satoshis.
        if let Lrc20TxType::Transfer { input_proofs, .. } = &tx_type {
            self.tx_signer.sign(&mut psbt, input_proofs)?;
        } else if let Lrc20TxType::Issue { .. } = &tx_type {
            // Offset is basically the number of regular Bitcoin inputs that we need to skip
            // while constructing input proofs.

            let input_proofs: ProofMap = input_proofs
                .into_values()
                .enumerate()
                .map(|(index, proof)| (index as u32, proof))
                .collect();

            self.tx_signer.sign(&mut psbt, &input_proofs)?;
        }

        let tx = psbt.extract_tx()?;
        let lrc20_tx = Lrc20Transaction {
            bitcoin_tx: tx,
            tx_type,
        };

        Ok(PyLrc20Transaction(lrc20_tx))
    }

    async fn build_sweep(&mut self, fee_rate_vb: f64) -> eyre::Result<Transaction> {
        let ctx = Secp256k1::new();

        let mut inputs = Vec::new();
        self.process_inputs(&ctx, &mut inputs).await?;

        let spend_tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut psbt = psbt::Psbt {
            unsigned_tx: spend_tx,
            unknown: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            xpub: BTreeMap::new(),
            version: 0,
            inputs: vec![],
            outputs: vec![],
        };

        let mut inputs_sum = 0;
        let mut total_weight = inputs[0].2;
        for (outpoint, _, weight) in &inputs {
            let builder_input = self
                .inputs
                .get(outpoint)
                .ok_or_eyre("Tweaked satoshis builder input is missing")?;

            let prev_tx = builder_input.prev_tx()?;

            inputs_sum += prev_tx.output[outpoint.vout as usize].value.to_sat();
            total_weight += weight;
        }

        let fee = fee_rate_vb as u64 * total_weight as u64;
        let output_sum = inputs_sum - fee;

        let pubkey = self.private_key.public_key(&ctx);
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

        psbt.outputs.push(Output::default());
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(output_sum),
            script_pubkey,
        });

        for (outpoint, psbt_input, _weight) in inputs.into_iter() {
            psbt.unsigned_tx.input.push(TxIn {
                previous_output: BitcoinOutPoint::from(outpoint),
                ..Default::default()
            });
            psbt.inputs.push(psbt_input);
        }

        let input_proofs = self
            .inputs
            .values()
            .filter_map(|input| match input {
                BuilderInput::TweakedSatoshis { outpoint, .. } => Some((
                    *outpoint,
                    Lrc20ReceiptProof::EmptyReceipt(EmptyReceiptProof::new(
                        self.private_key.public_key(&ctx).inner,
                    )),
                )),
                _ => None,
            })
            .collect::<HashMap<OutPoint, Lrc20ReceiptProof>>();

        let input_proofs: ProofMap = input_proofs
            .into_values()
            .enumerate()
            .map(|(index, proof)| (index as u32, proof))
            .collect();

        self.tx_signer.sign(&mut psbt, &input_proofs)?;

        let tx = psbt.extract_tx()?;

        Ok(tx)
    }

    /// Go through inputs, and form list of inputs for BDK.
    ///
    /// Also, store keys that will be used for signing.
    async fn process_inputs(
        &mut self,
        ctx: &Secp256k1<All>,
        inputs: &mut Vec<(OutPoint, psbt::Input, usize)>,
    ) -> eyre::Result<()> {
        for (outpoint, input) in &self.inputs {
            let prev_tx = input.prev_tx()?;
            let output = prev_tx
                .output
                .get(outpoint.vout as usize)
                .ok_or_eyre("Previous transaction doesn't have such a vout")?;

            let mut psbt_input = psbt::Input {
                sighash_type: None,
                witness_utxo: Some(output.clone()),
                ..Default::default()
            };

            // Get descriptor and secret keys depending on the input type
            let (descriptor, secret_keys) = self.get_descriptor_and_keys_for_input(ctx, input)?;

            // Extend list of signers
            self.tx_signer.extend_signers(secret_keys);

            let derived = descriptor.at_derivation_index(0)?;

            if !matches!(input, BuilderInput::Satoshis { .. }) {
                psbt_input.update_with_descriptor_unchecked(&derived)?;
            }

            if let BuilderInput::TaprootReceipt { proof, .. } = input {
                let taproot_proof = TaprootProof::new(
                    proof.receipt()?,
                    PublicKey::from_str(&proof.inner_key)?,
                    None,
                );
                psbt_input.witness_script = Some(taproot_proof.to_witness_script()?);
            }

            let weight = derived.max_weight_to_satisfy()?;

            inputs.push((*outpoint, psbt_input, weight));
        }

        Ok(())
    }

    /// Return descriptor for input and return map of keys that will be used for
    /// singing input after transaction is built.
    fn get_descriptor_and_keys_for_input(
        &self,
        ctx: &Secp256k1<All>,
        input: &BuilderInput,
    ) -> eyre::Result<(
        Descriptor<DescriptorPublicKey>,
        HashMap<XOnlyPublicKey, secp256k1::SecretKey>,
    )> {
        // Store private keys for future signing.
        let mut keys = HashMap::new();

        let pubkey1 = self.private_key.public_key(ctx);
        keys.insert(pubkey1.inner.into(), self.private_key.inner);

        // Keys keys depending of input type, and create descriptors on that.
        let (descriptor, _secret_keys, _) = match input {
            BuilderInput::Receipt { proof, .. } => {
                let tweaked_pubkey =
                    ReceiptKey::new_with_ctx(proof.receipt()?, &pubkey1.inner, ctx)?;

                descriptor!(wpkh(tweaked_pubkey.to_public_key()))?
            }
            BuilderInput::TweakedSatoshis { .. } => {
                let tweaked_pubkey =
                    ReceiptKey::new_with_ctx(Receipt::empty(), &pubkey1.inner, ctx)?;

                descriptor!(wpkh(tweaked_pubkey.to_public_key()))?
            }
            BuilderInput::Satoshis { .. } => descriptor!(wpkh(pubkey1))?,
            BuilderInput::TaprootReceipt { proof, .. } => {
                let (tweaked_xonly_pubkey, _) =
                    ReceiptKey::new_with_ctx(proof.receipt()?, &pubkey1.inner, ctx)?
                        .x_only_public_key();

                descriptor!(tr(tweaked_xonly_pubkey))?
            }
        };

        Ok((descriptor, keys))
    }

    /// Add output to the bitcoin transactions and list of output proofs.
    fn process_output(
        &self,
        output: &BuilderOutput,
        output_proofs: &mut Vec<Lrc20ReceiptProof>,
        outputs: &mut Vec<(ScriptBuf, u64)>,
    ) -> eyre::Result<()> {
        let (script_pubkey, satoshis) = match output {
            // For receipt, form script and push proof of it to the list
            BuilderOutput::Receipt {
                token_pubkey,
                satoshis,
                amount,
                recipient,
            } => {
                let receipt = Receipt::new(*amount, *token_pubkey);
                let receipt_key = ReceiptKey::new(receipt, recipient)?;

                let script_pubkey = receipt_key
                    .to_p2wpkh()
                    .ok_or_eyre("Receipt key is not compressed")?;

                let receipt_proof = SigReceiptProof::new(receipt, *recipient, None);

                output_proofs.push(receipt_proof.into());

                (script_pubkey, *satoshis)
            }
            BuilderOutput::TaprootReceipt {
                token_pubkey,
                satoshis,
                amount,
                recipient,
            } => {
                let receipt = Receipt::new(*amount, *token_pubkey);
                let receipt_key = ReceiptKey::new(receipt, recipient)?;

                let ctx = Secp256k1::new();
                let script_pubkey = ScriptBuf::new_p2tr(&ctx, receipt_key.to_x_only_pubkey(), None);

                let receipt_proof = TaprootProof::new(receipt, *recipient, None);

                output_proofs.push(receipt_proof.into());

                (script_pubkey, *satoshis)
            }
        };

        outputs.push((script_pubkey, satoshis));

        Ok(())
    }
}

pub fn form_issue_announcement(
    output_proofs: Vec<Lrc20ReceiptProof>,
) -> eyre::Result<IssueAnnouncement> {
    let filtered_proofs = output_proofs
        .into_iter()
        .filter(|proof| !proof.is_empty_receiptproof())
        .collect::<Vec<Lrc20ReceiptProof>>();

    let token_pubkey = filtered_proofs
        .first()
        .map(|proof| proof.receipt().token_pubkey)
        .ok_or_eyre("issuance with no outputs")?;

    let outputs_sum = filtered_proofs
        .iter()
        .map(|proof| proof.receipt().token_amount.amount)
        .sum::<u128>();

    Ok(IssueAnnouncement {
        token_pubkey,
        amount: outputs_sum,
    })
}

/// Generate an empty receipt proof using the given `PublicKey` and an empty `Receipt`.
fn get_empty_receipt_proof(
    recipient: secp256k1::PublicKey,
) -> eyre::Result<(Lrc20ReceiptProof, ScriptBuf)> {
    let receipt_key = ReceiptKey::new(Receipt::empty(), &recipient)?;

    let script_pubkey = receipt_key
        .to_p2wpkh()
        .ok_or_eyre("Receipt key is not compressed")?;

    Ok((
        Lrc20ReceiptProof::EmptyReceipt(EmptyReceiptProof::new(recipient)),
        script_pubkey,
    ))
}

fn form_tx_type(
    unsigned_tx: &Transaction,
    input_proofs: &HashMap<OutPoint, Lrc20ReceiptProof>,
    output_proofs: &[Lrc20ReceiptProof],
    is_issuance: bool,
) -> eyre::Result<Lrc20TxType> {
    let mut mapped_input_proofs = BTreeMap::new();

    for (index, input) in unsigned_tx.input.iter().enumerate() {
        let Some(input_proof) = input_proofs.get(&input.previous_output.into()) else {
            continue;
        };

        mapped_input_proofs.insert(index as u32, input_proof.clone());
    }

    let offset = if is_issuance { 1 } else { 0 };
    let output_proofs = output_proofs
        .iter()
        .enumerate()
        .map(|(index, proof)| ((index + offset) as u32, proof.clone()))
        .collect::<BTreeMap<u32, Lrc20ReceiptProof>>();

    let tx_type = if is_issuance {
        let issue_announcement =
            form_issue_announcement(output_proofs.clone().into_values().collect())?;

        Lrc20TxType::Issue {
            output_proofs: Some(output_proofs),
            announcement: issue_announcement,
        }
    } else {
        Lrc20TxType::Transfer {
            input_proofs: mapped_input_proofs,
            output_proofs,
        }
    };

    Ok(tx_type)
}
