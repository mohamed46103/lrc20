use std::{
    collections::{BTreeMap, HashMap},
    future, mem,
    sync::{Arc, RwLock},
};

use bitcoin::{
    OutPoint, PrivateKey, PublicKey, ScriptBuf, Transaction, TxOut,
    key::XOnlyPublicKey,
    psbt,
    secp256k1::{self, All, Secp256k1},
};
use eyre::{Context, OptionExt, bail, eyre};

#[cfg(feature = "bulletproof")]
use {
    bitcoin::secp256k1::schnorr::Signature,
    lrc20_receipts::{Bulletproof, RangeProof, TokenAmount, k256::ProjectivePoint},
    lrc20_types::is_bulletproof,
};

use bdk::{
    FeeRate as BdkFeeRate, SignOptions,
    blockchain::Blockchain,
    descriptor,
    miniscript::{Descriptor, DescriptorPublicKey, ToPublicKey, psbt::PsbtInputExt},
    wallet::tx_builder::TxOrdering,
};

use futures::TryStreamExt;
use lrc20_receipts::{
    EmptyReceiptProof, MultisigReceiptProof, Receipt, ReceiptHash, ReceiptKey, ReceiptProof,
    SigReceiptProof, TaprootProof, TokenPubkey, ZERO_PUBLIC_KEY,
};
use serde_json::Value;

use lrc20_types::{AnyAnnouncement, announcements::IssueAnnouncement};
use lrc20_types::{Lrc20Transaction, Lrc20TxType, ProofMap};

use crate::{
    Wallet,
    bitcoin_provider::BitcoinProvider,
    database::WalletStorage,
    lrc20_coin_selection::{LRC20CoinSelectionAlgorithm, Lrc20LargestFirstCoinSelection},
    txsigner::TransactionSigner,
    types::{FeeRateStrategy, Lrc20TxOut, Lrc20Utxo, Utxo, WeightedUtxo},
};

#[cfg(feature = "bulletproof")]
mod bulletproof;
#[cfg(feature = "bulletproof")]
pub use bulletproof::BulletproofRecipientParameters;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum BuilderInput {
    Multisig2x2 {
        outpoint: OutPoint,
        second_signer_key: PrivateKey,
    },
    TaprootReceipt {
        outpoint: OutPoint,
    },
    SparkExitScript {
        outpoint: OutPoint,
    },
    Receipt {
        outpoint: OutPoint,
    },
    TweakedSatoshis {
        outpoint: OutPoint,
    },
    #[cfg(feature = "bulletproof")]
    BulletproofReceipt {
        outpoint: OutPoint,
    },
}

impl BuilderInput {
    fn outpoint(&self) -> OutPoint {
        match self {
            BuilderInput::Multisig2x2 { outpoint, .. }
            | BuilderInput::Receipt { outpoint }
            | BuilderInput::TweakedSatoshis { outpoint }
            | BuilderInput::TaprootReceipt { outpoint }
            | BuilderInput::SparkExitScript { outpoint } => *outpoint,
            #[cfg(feature = "bulletproof")]
            BuilderInput::BulletproofReceipt { outpoint, .. } => *outpoint,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum BuilderOutput {
    Satoshis {
        satoshis: u64,
        recipient: secp256k1::PublicKey,
    },
    Receipt {
        token_pubkey: TokenPubkey,
        satoshis: u64,
        amount: u128,
        recipient: secp256k1::PublicKey,
        metadata: Option<Value>,
    },
    MultisigReceipt {
        token_pubkey: TokenPubkey,
        satoshis: u64,
        amount: u128,
        participants: Vec<secp256k1::PublicKey>,
        required_signatures: u8,
    },
    TaprootReceipt {
        token_pubkey: TokenPubkey,
        satoshis: u64,
        amount: u128,
        recipient: secp256k1::PublicKey,
        metadata: Option<Value>,
    },
    #[cfg(feature = "bulletproof")]
    BulletproofReceipt {
        token_pubkey: TokenPubkey,
        recipient: PublicKey,
        sender: PublicKey,
        token_amount: TokenAmount,
        satoshis: u64,
        commitment: ProjectivePoint,
        proof: RangeProof,
        signature: Signature,
        token_pubkey_signature: Signature,
    },
}

impl BuilderOutput {
    fn amount(&self) -> u128 {
        match self {
            BuilderOutput::Satoshis { .. } => 0,
            BuilderOutput::Receipt { amount, .. }
            | BuilderOutput::MultisigReceipt { amount, .. } => *amount,
            BuilderOutput::TaprootReceipt { amount, .. } => *amount,
            #[cfg(feature = "bulletproof")]
            BuilderOutput::BulletproofReceipt { .. } => 0,
        }
    }

    fn token_pubkey(&self) -> Option<TokenPubkey> {
        match self {
            BuilderOutput::Satoshis { .. } => None,
            BuilderOutput::Receipt { token_pubkey, .. } => Some(*token_pubkey),
            BuilderOutput::TaprootReceipt { token_pubkey, .. } => Some(*token_pubkey),
            BuilderOutput::MultisigReceipt { token_pubkey, .. } => Some(*token_pubkey),
            #[cfg(feature = "bulletproof")]
            BuilderOutput::BulletproofReceipt { token_pubkey, .. } => Some(*token_pubkey),
        }
    }
}

struct TransactionBuilder<WalletStorage, BitcoinTxsDatabase> {
    /// Defines if the transactions is issuance or not.
    ///
    /// By that [`TransactionBuilder`] will consider to whether add or not the
    /// inputs with LRC20 coins to satisfy conservation rules.
    is_issuance: bool,

    /// [`TokenPubkeys`]s of current transactions.
    token_pubkeys: Vec<TokenPubkey>,

    /// Value of satoshis that will be attached to change output for LRC20 coins.
    change_satoshis: u64,

    /// The fee rate strategy. Possible values:
    /// - Estimate: The fee rate is fetched from Bitcoin RPC. If an error
    ///   occurs, the tx building process is interrupted.
    /// - Manual: Default fee rate is used.
    /// - TryEstimate: The fee rate is fetched
    ///   automatically from Bitcoin RPC. If an error occurs, the default fee rate is used.
    ///   NOTE: fee_rate is measured in sat/vb.
    fee_rate_strategy: FeeRateStrategy,

    storage: WalletStorage,

    /// Inner wallet which will sign result transaction.
    inner_wallet: Arc<RwLock<bdk::Wallet<BitcoinTxsDatabase>>>,
    private_key: PrivateKey,

    /// Storage of outputs which will be formed into transaction outputs and
    /// proofs.
    outputs: Vec<BuilderOutput>,

    /// Storage of bulletproof outputs that will be mapped to `self.outputs` and then into transaction outputs and
    /// proofs.
    ///
    /// `OutPoint` is an `Option` as it may be absent in case the transaction is an issuance.
    #[cfg(feature = "bulletproof")]
    bulletproof_outputs:
        BTreeMap<Option<OutPoint>, Vec<(TokenPubkey, bulletproof::BulletproofRecipientParameters)>>,

    /// Storage of inputs which will be formed into transaction inputs and
    /// proofs.
    inputs: Vec<BuilderInput>,

    /// Transaction Signer is responsible for signing the transaction.
    tx_signer: TransactionSigner,

    /// Indicated if inputs were selected by user.
    is_inputs_selected: bool,

    /// Instructs txbuilder to add tweaked satoshis as transaction inputs
    should_drain_tweaked_satoshis: bool,
}

unsafe impl<Lrc20TxsDatabase, BitcoinTxsDatabase> Sync
    for TransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>
where
    Lrc20TxsDatabase: Sync,
    BitcoinTxsDatabase: Sync,
{
}

unsafe impl<Lrc20TxsDatabase, BitcoinTxsDatabase> Send
    for TransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>
where
    Lrc20TxsDatabase: Send,
    BitcoinTxsDatabase: Send,
{
}

pub struct SweepTransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>(
    TransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>,
);

impl<WS, BDB, YC, BP> TryFrom<&Wallet<YC, WS, BP, BDB>> for SweepTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
    BP: BitcoinProvider,
{
    type Error = eyre::Error;

    fn try_from(wallet: &Wallet<YC, WS, BP, BDB>) -> Result<Self, Self::Error> {
        Ok(Self(TransactionBuilder::new(true, wallet)?))
    }
}

impl<WS, BDB> SweepTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Override the fee rate strategy.
    pub fn set_fee_rate_strategy(&mut self, fee_rate_strategy: FeeRateStrategy) -> &mut Self {
        self.0.set_fee_rate_strategy(fee_rate_strategy);

        self
    }

    /// Finish sweep building, and create a Bitcoin transaction.
    /// If the address has no tweaked Bitcoin outputs, `None` is returned.
    pub async fn finish(self, blockchain: &impl Blockchain) -> eyre::Result<Option<Transaction>> {
        self.0.build_sweep(blockchain).await
    }
}

pub struct IssuanceTransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase> {
    tx_builder: TransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>,
    token_pubkey: TokenPubkey,
}

impl<WS, BDB> IssuanceTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    pub fn new<BP: BitcoinProvider, YC>(
        wallet: &Wallet<YC, WS, BP, BDB>,
        token_pubkey: Option<TokenPubkey>,
    ) -> eyre::Result<Self> {
        let tx_builder = TransactionBuilder::new(true, wallet)?;
        let token_pubkey = token_pubkey.unwrap_or(tx_builder.issuance_token_pubkey());
        Ok(Self {
            tx_builder,
            token_pubkey,
        })
    }
}

impl<WS, BDB> IssuanceTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Add recipient to the transaction.
    pub fn add_recipient(
        &mut self,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.tx_builder.outputs.push(BuilderOutput::Receipt {
            token_pubkey: self.token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: None,
        });

        self
    }

    /// Add recipient to the transaction.
    pub fn add_recipient_with_metadata(
        &mut self,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
        metadata: impl Into<Value>,
    ) -> eyre::Result<&mut Self> {
        self.tx_builder.outputs.push(BuilderOutput::Receipt {
            token_pubkey: self.token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: Some(metadata.into()),
        });

        Ok(self)
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient(
        &mut self,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.tx_builder
            .add_taproot_recipient(self.token_pubkey, recipient, amount, satoshis);

        self
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient_with_metadata(
        &mut self,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
        metadata: impl Into<Value>,
    ) -> eyre::Result<&mut Self> {
        self.tx_builder.add_taproot_recipient_with_metadata(
            self.token_pubkey,
            recipient,
            amount,
            satoshis,
            metadata,
        )?;

        Ok(self)
    }

    /// Override the fee rate strategy.
    pub fn set_fee_rate_strategy(&mut self, fee_rate_strategy: FeeRateStrategy) -> &mut Self {
        self.tx_builder.set_fee_rate_strategy(fee_rate_strategy);

        self
    }

    // Override spending tweaked satoshis
    pub fn set_drain_tweaked_satoshis(&mut self, should_drain_tweaked_satoshis: bool) -> &mut Self {
        self.tx_builder.should_drain_tweaked_satoshis = should_drain_tweaked_satoshis;
        self
    }

    /// Add satoshi recipient.
    pub fn add_sats_recipient(
        &mut self,
        recipient: &secp256k1::PublicKey,
        satoshis: u64,
    ) -> &mut Self {
        self.tx_builder.add_sats_recipient(recipient, satoshis);

        self
    }

    /// Add multisig recipient to the transaction.
    ///
    /// The transaction output will be formed as P2WSH output with
    /// multisignature script, that has tweaked first key.
    pub fn add_multisig_recipient(
        &mut self,
        participants: Vec<secp256k1::PublicKey>,
        required_signatures: u8,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.tx_builder.add_multisig_recipient(
            participants,
            required_signatures,
            amount,
            self.token_pubkey,
            satoshis,
        );

        self
    }

    /// Finish issuance building, and create Bitcoin transactions with attached
    /// proofs for it in [`Lrc20Transaction`].
    pub async fn finish(self, blockchain: &impl Blockchain) -> eyre::Result<Lrc20Transaction> {
        self.tx_builder.finish(blockchain).await
    }
}

pub struct TransferTransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>(
    TransactionBuilder<Lrc20TxsDatabase, BitcoinTxsDatabase>,
);

impl<WS, BDB, YC, BP> TryFrom<&Wallet<YC, WS, BP, BDB>> for TransferTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
    BP: BitcoinProvider,
{
    type Error = eyre::Error;

    fn try_from(wallet: &Wallet<YC, WS, BP, BDB>) -> Result<Self, Self::Error> {
        Ok(Self(TransactionBuilder::new(false, wallet)?))
    }
}

impl<WS, BDB> TransferTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Add recipient to the transaction.
    pub fn add_recipient(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.0.outputs.push(BuilderOutput::Receipt {
            token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: None,
        });

        self.0.token_pubkeys.push(token_pubkey);

        self
    }

    /// Add recipient to the transaction.
    pub fn add_recipient_with_metadata(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
        metadata: impl Into<Value>,
    ) -> eyre::Result<&mut Self> {
        self.0.outputs.push(BuilderOutput::Receipt {
            token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: Some(metadata.into()),
        });

        self.0.token_pubkeys.push(token_pubkey);

        Ok(self)
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.0
            .add_taproot_recipient(token_pubkey, recipient, amount, satoshis);

        self
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient_with_metadata(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
        metadata: impl Into<Value>,
    ) -> eyre::Result<&mut Self> {
        self.0.add_taproot_recipient_with_metadata(
            token_pubkey,
            recipient,
            amount,
            satoshis,
            Some(metadata.into()),
        )?;

        Ok(self)
    }

    /// Set the burn amount.
    pub fn set_burn_amount(
        &mut self,
        token_pubkey: TokenPubkey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.0.outputs.push(BuilderOutput::Receipt {
            token_pubkey,
            satoshis,
            amount,
            recipient: *ZERO_PUBLIC_KEY,
            metadata: None,
        });

        self.0.token_pubkeys.push(token_pubkey);

        self
    }

    /// Override the fee rate strategy.
    pub fn set_fee_rate_strategy(&mut self, fee_rate_strategy: FeeRateStrategy) -> &mut Self {
        self.0.fee_rate_strategy = fee_rate_strategy;
        self
    }

    // Override spending tweaked satoshis
    pub fn set_drain_tweaked_satoshis(&mut self, should_drain_tweaked_satoshis: bool) -> &mut Self {
        self.0.should_drain_tweaked_satoshis = should_drain_tweaked_satoshis;
        self
    }

    /// Add satoshi recipient.
    pub fn add_sats_recipient(
        &mut self,
        recipient: &secp256k1::PublicKey,
        satoshis: u64,
    ) -> &mut Self {
        self.0.add_sats_recipient(recipient, satoshis);

        self
    }

    /// Add a 2x2 multisignature input.
    pub fn add_2x2multisig_input(
        &mut self,
        outpoint: OutPoint,
        spender_key2: PrivateKey,
    ) -> &mut Self {
        self.0.add_2x2multisig_input(outpoint, spender_key2);

        self
    }

    /// Add a taproot input.
    pub fn add_taproot_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.0.add_taproot_input(outpoint);

        self
    }

    /// Add spark exit script path input.
    pub fn add_spark_script_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.0.add_spark_script_input(outpoint);

        self
    }

    /// Add multisig recipient to the transaction.
    ///
    /// The transaction output will be formed as P2WSH output with
    /// multisignature script, that has tweaked first key.
    pub fn add_multisig_recipient(
        &mut self,
        participants: Vec<secp256k1::PublicKey>,
        required_signatures: u8,
        amount: u128,
        token_pubkey: TokenPubkey,
        satoshis: u64,
    ) -> &mut Self {
        self.0.add_multisig_recipient(
            participants,
            required_signatures,
            amount,
            token_pubkey,
            satoshis,
        );

        self
    }

    /// Set flag that only selected inputs will be used for transaction
    pub fn manual_selected_only(&mut self) {
        self.0.manual_selected_only();
    }

    /// Set amount of satoshis that will be given to residual output for LRC20 coins.
    pub fn set_change_satoshis(&mut self, satoshis: u64) -> &mut Self {
        self.0.set_change_satoshis(satoshis);

        self
    }

    /// Add receipt input to the transaction with given outpoint.
    pub fn add_receipt_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.0.add_receipt_input(outpoint);

        self
    }

    /// Finish transfer building, and create Bitcoin transactions with attached
    /// proofs for it in [`Lrc20Transaction`].
    pub async fn finish(self, blockchain: &impl Blockchain) -> eyre::Result<Lrc20Transaction> {
        self.0.finish(blockchain).await
    }
}

impl<WS, BDB> TransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    fn new<YC, BC>(is_issuance: bool, wallet: &Wallet<YC, WS, BC, BDB>) -> eyre::Result<Self> {
        let bitcoin_wallet = wallet.bitcoin_wallet.clone();

        let ctx = { bitcoin_wallet.read().unwrap().secp_ctx().clone() };

        Ok(Self {
            is_issuance,
            token_pubkeys: Vec::new(),
            change_satoshis: 1000,
            fee_rate_strategy: FeeRateStrategy::default(),
            inner_wallet: bitcoin_wallet,
            private_key: wallet.signer_key,
            storage: wallet.storage.clone(),
            outputs: Vec::new(),
            #[cfg(feature = "bulletproof")]
            bulletproof_outputs: BTreeMap::new(),
            inputs: Vec::new(),
            tx_signer: TransactionSigner::new(ctx, wallet.signer_key),
            is_inputs_selected: false,
            should_drain_tweaked_satoshis: false,
        })
    }
}

impl<WS, BDB> TransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    fn add_sats_recipient(&mut self, recipient: &secp256k1::PublicKey, satoshis: u64) -> &mut Self {
        self.outputs.push(BuilderOutput::Satoshis {
            satoshis,
            recipient: *recipient,
        });

        self
    }

    /// Add 2 from 2 multsig input to the transaction with given outpoint.
    ///
    /// The proof will be taken from synced LRC20 transactions.
    fn add_2x2multisig_input(&mut self, outpoint: OutPoint, spender_key2: PrivateKey) -> &mut Self {
        self.inputs.push(BuilderInput::Multisig2x2 {
            outpoint,
            second_signer_key: spender_key2,
        });

        self
    }

    /// Add a Taproot input to the transaction with given outpoint.
    fn add_taproot_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.inputs.push(BuilderInput::TaprootReceipt { outpoint });

        self
    }

    /// Add spark exit script path input.
    fn add_spark_script_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.inputs.push(BuilderInput::SparkExitScript { outpoint });

        self
    }

    /// Add multisig recipient to the transaction.
    ///
    /// The transaction output will be formed as P2WSH output with
    /// multisignature script, that has tweaked first key.
    pub fn add_multisig_recipient(
        &mut self,
        participants: Vec<secp256k1::PublicKey>,
        required_signatures: u8,
        amount: u128,
        token_pubkey: TokenPubkey,
        satoshis: u64,
    ) -> &mut Self {
        debug_assert!(
            participants.len() > 1 && participants.len() < 16,
            "Invalid number of participants"
        );
        self.outputs.push(BuilderOutput::MultisigReceipt {
            token_pubkey,
            satoshis,
            amount,
            required_signatures,
            participants,
        });

        self.token_pubkeys.push(token_pubkey);

        self
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
    ) -> &mut Self {
        self.outputs.push(BuilderOutput::TaprootReceipt {
            token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: None,
        });

        self.token_pubkeys.push(token_pubkey);

        self
    }

    /// Add a p2tr recipient to the transaction.
    pub fn add_taproot_recipient_with_metadata(
        &mut self,
        token_pubkey: TokenPubkey,
        recipient: &secp256k1::PublicKey,
        amount: u128,
        satoshis: u64,
        metadata: impl Into<Value>,
    ) -> eyre::Result<&mut Self> {
        self.outputs.push(BuilderOutput::TaprootReceipt {
            token_pubkey,
            satoshis,
            amount,
            recipient: *recipient,
            metadata: Some(metadata.into()),
        });

        Ok(self)
    }

    /// Add receipt input to the transaction with given outpoint.
    fn add_receipt_input(&mut self, outpoint: OutPoint) -> &mut Self {
        self.inputs.push(BuilderInput::Receipt { outpoint });
        self
    }

    async fn add_tweaked_satoshi_inputs(&mut self) -> eyre::Result<()> {
        let tweaked_outputs = self
            .storage
            .stream_unspent_lrc20_outputs()
            .await
            .try_filter_map(|(outpoint, (proof, _))| {
                future::ready(Ok(proof.is_empty_receiptproof().then_some(outpoint)))
            })
            .try_collect::<Vec<_>>()
            .await?;

        for outpoint in tweaked_outputs {
            self.inputs.push(BuilderInput::TweakedSatoshis { outpoint });
        }

        Ok(())
    }

    /// Set amount of satoshis that will be given to residual output for LRC20 coins.
    fn set_change_satoshis(&mut self, satoshis: u64) -> &mut Self {
        self.change_satoshis = satoshis;
        self
    }

    /// Override the fee rate strategy.
    fn set_fee_rate_strategy(&mut self, fee_rate_strategy: FeeRateStrategy) -> &mut Self {
        self.fee_rate_strategy = fee_rate_strategy;
        self
    }

    fn issuance_token_pubkey(&self) -> TokenPubkey {
        self.private_key.public_key(&Secp256k1::new()).into()
    }

    // === Finish transaction building ===
    async fn finish(mut self, blockchain: &impl Blockchain) -> eyre::Result<Lrc20Transaction> {
        let fee_rate = self
            .fee_rate_strategy
            .get_fee_rate(blockchain)
            .wrap_err("failed to estimate fee")?;

        if !self.is_inputs_selected {
            if self.should_drain_tweaked_satoshis {
                self.add_tweaked_satoshi_inputs().await?;
            }
            if !self.is_issuance {
                for token_pubkey in &self.token_pubkeys.clone() {
                    self.fill_missing_amount(*token_pubkey).await?;
                }
            }
        }

        self.build_tx(fee_rate).await
    }

    /// Fill [`Self::inputs`] with missing utxos that will be used to satisfy
    /// sum in [`Self::outputs`].
    ///
    /// Also will add to [`Self::outputs`] self-recipient for residual LRC20 coins
    /// if need so.
    async fn fill_missing_amount(&mut self, token_pubkey: TokenPubkey) -> eyre::Result<()> {
        let output_sum = self
            .outputs
            .iter()
            .filter(|output| output.token_pubkey() == Some(token_pubkey))
            .map(|output| output.amount())
            .sum::<u128>();

        let input_sum = self.inputs_sum(token_pubkey).await?;

        // No work is required if sum of inputs is equal to sum of outputs
        if input_sum == output_sum {
            return Ok(());
        }

        // If sum of inputs is greater than sum of outputs, then we need to
        // add self-recipient for residual amount.
        if input_sum > output_sum {
            let residual_amount = input_sum.saturating_sub(output_sum);

            // If remaining amount is not zero, add self-recipient
            self.add_change_output(token_pubkey, residual_amount)?;

            return Ok(());
        }

        // Otherwise, we need to add inputs to satisfy sum of outputs
        let required_utxos = self
            .form_weighted_utxos(
                self.inputs
                    .iter()
                    .map(BuilderInput::outpoint)
                    .collect::<Vec<_>>(),
                token_pubkey,
            )
            .await?;

        let optional_utxos = self.form_weighted_utxos_from_storage(token_pubkey).await?;

        let target_amount = output_sum.saturating_sub(input_sum);

        debug_assert!(target_amount > 0, "Target amount is zero");

        let selection_result = Lrc20LargestFirstCoinSelection.coin_select(
            required_utxos,
            optional_utxos,
            target_amount,
            &ScriptBuf::new(),
            token_pubkey,
        )?;

        for selected in selection_result.selected {
            if selected.lrc20_txout().script_pubkey.is_p2tr() {
                let p2tr_input = if selected.lrc20_txout().is_spark {
                    BuilderInput::SparkExitScript {
                        outpoint: selected.outpoint(),
                    }
                } else {
                    BuilderInput::TaprootReceipt {
                        outpoint: selected.outpoint(),
                    }
                };
                self.inputs.push(p2tr_input);
                continue;
            }
            self.inputs.push(BuilderInput::Receipt {
                outpoint: selected.outpoint(),
            });
            // Here we are sure, that selected utxo is single-sig receipt
        }

        let filled_input_sum = input_sum + selection_result.amount;

        if filled_input_sum < output_sum {
            bail!(
                "Insufficient balance: inputs sum: {} output sum: {}",
                filled_input_sum,
                output_sum
            );
        }

        let change_amount = filled_input_sum.saturating_sub(output_sum);

        // If remaining amount is not zero, add self-recipient
        if change_amount > 0 {
            self.add_change_output(token_pubkey, change_amount)?;
        }

        Ok(())
    }

    fn add_change_output(
        &mut self,
        token_pubkey: TokenPubkey,
        residual_amount: u128,
    ) -> eyre::Result<()> {
        debug_assert!(residual_amount > 0, "Residual amount is zero");

        let ctx = Secp256k1::new();

        self.outputs.push(BuilderOutput::Receipt {
            token_pubkey,
            satoshis: self.change_satoshis,
            amount: residual_amount,
            recipient: self.private_key.public_key(&ctx).inner,
            metadata: None,
        });

        Ok(())
    }

    async fn inputs_sum(&self, token_pubkey: TokenPubkey) -> eyre::Result<u128> {
        let mut sum = 0u128;

        for input in &self.inputs {
            let (proof, _) = self
                .storage
                .get_unspent_lrc20_output(input.outpoint())
                .await?;

            let receipt = proof.receipt();

            if receipt.token_pubkey != token_pubkey {
                continue;
            }

            sum = sum
                .checked_add(receipt.token_amount.amount)
                .ok_or_eyre("Inputs sum overflow")?;
        }

        Ok(sum)
    }

    /// Form [`WeightedUtxo`] for LRC20 coins from given [`OutPoint`]s from
    /// unspent transaction outputs.
    async fn form_weighted_utxos(
        &self,
        outpoints: impl IntoIterator<Item = OutPoint>,
        token_pubkey: TokenPubkey,
    ) -> eyre::Result<Vec<WeightedUtxo>> {
        let mut weighted_utxos = Vec::new();

        for outpoint in outpoints {
            let (proof, txout) = self
                .storage
                .try_get_unspent_lrc20_output(outpoint)
                .await?
                .ok_or_eyre("No such outpoint")?;

            optionally_add_weighted_utxo(outpoint, proof, txout, token_pubkey, &mut weighted_utxos);
        }

        Ok(weighted_utxos)
    }

    async fn form_weighted_utxos_from_storage(
        &self,
        token_pubkey: TokenPubkey,
    ) -> eyre::Result<Vec<WeightedUtxo>> {
        let mut weighted_utxos = Vec::new();

        let mut stream = self.storage.stream_unspent_lrc20_outputs().await;

        while let Some((outpoint, (proof, txout))) = stream.try_next().await? {
            optionally_add_weighted_utxo(outpoint, proof, txout, token_pubkey, &mut weighted_utxos);
        }

        Ok(weighted_utxos)
    }

    /// Set flag that only selected inputs will be used for transaction
    fn manual_selected_only(&mut self) {
        self.is_inputs_selected = true;
    }

    /// Inserts empty receipt proofs to the outputs that don't hold any Receipt data,
    /// i.e. to the Satoshis only outputs.
    ///
    /// The output `script_pubkey` is also tweaked with an empty receipt, so the method
    /// creates wrapped satoshis that can be spent after sweeping them to a p2wpkh address.
    fn insert_empty_receiptproofs(
        &self,
        output_proofs: &mut Vec<ReceiptProof>,
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

    async fn build_sweep(
        mut self,
        blockchain: &impl Blockchain,
    ) -> eyre::Result<Option<Transaction>> {
        let fee_rate = self
            .fee_rate_strategy
            .get_fee_rate(blockchain)
            .wrap_err("failed to estimate fee")?;
        let ctx = Secp256k1::new();

        // Get the tweaked UTXOs.
        let mut tweaked_outputs = self
            .storage
            .stream_unspent_lrc20_outputs()
            .await
            .map_ok(|(outpoint, (proof, _))| (outpoint, proof))
            .try_filter(|(_, proof)| future::ready(proof.is_empty_receiptproof()))
            .try_collect::<HashMap<_, _>>()
            .await?;

        // If there are no tweaked UTXOs, then exit.
        if tweaked_outputs.is_empty() {
            return Ok(None);
        }

        for outpoint in tweaked_outputs.keys() {
            self.inputs.push(BuilderInput::TweakedSatoshis {
                outpoint: *outpoint,
            })
        }

        let mut inputs = Vec::new();
        self.process_inputs(&ctx, &mut tweaked_outputs, &mut inputs)
            .await?;

        let bitcoin_wallet = self.inner_wallet.read().unwrap();
        let mut tx_builder = bitcoin_wallet.build_tx();
        tx_builder.only_witness_utxo();
        tx_builder.fee_rate(fee_rate);

        for (outpoint, psbt_input, weight) in &inputs {
            tx_builder.add_foreign_utxo(*outpoint, psbt_input.clone(), *weight)?;
        }

        // Calculate the inputs sum and fee.
        let mut inputs_sum = 0;
        let mut total_weight = inputs[0].2;
        for (outpoint, _, weight) in inputs {
            let tx = blockchain
                .get_tx(&outpoint.txid)?
                .ok_or_else(|| eyre!("Transaction {} was not found", outpoint.txid))?;

            let output = &tx.output.get(outpoint.vout as usize).ok_or_else(|| {
                eyre!(
                    "Transaction {} doesn't contain vout {}",
                    outpoint.txid,
                    outpoint.vout
                )
            })?;

            inputs_sum += output.value.to_sat();
            total_weight += weight;
        }

        let fee = fee_rate.as_sat_per_vb() as u64 * total_weight as u64;
        let output_sum = inputs_sum - fee;

        let pubkey = self.private_key.public_key(&ctx);
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());

        tx_builder.add_recipient(script_pubkey, output_sum);

        let (mut psbt, _details) = tx_builder.finish()?;

        bitcoin_wallet.sign(
            &mut psbt,
            SignOptions {
                try_finalize: true,
                trust_witness_utxo: true,
                ..Default::default()
            },
        )?;

        let input_proofs = tweaked_outputs
            .iter()
            .enumerate()
            .map(|(i, (_, proof))| (i as u32, proof.clone()))
            .collect::<ProofMap>();

        self.tx_signer.sign(&mut psbt, &input_proofs)?;

        Ok(Some(psbt.extract_tx()?))
    }

    async fn build_tx(mut self, fee_rate: BdkFeeRate) -> eyre::Result<Lrc20Transaction> {
        let ctx = Secp256k1::new();

        // Gather inputs as foreighn utxos with proofs for BDK wallet.
        let mut input_proofs = HashMap::new();
        let mut inputs = Vec::new();

        self.process_inputs(&ctx, &mut input_proofs, &mut inputs)
            .await?;

        #[cfg(feature = "bulletproof")]
        if !self.bulletproof_outputs.is_empty() {
            self.process_bulletproof_outputs(
                &input_proofs
                    .iter()
                    .filter_map(|(outpoint, proof)| {
                        proof
                            .get_bulletproof()
                            .map(|bulletproof| (*outpoint, bulletproof.clone()))
                    })
                    .collect(),
            )?;
        }

        // Gather output `script_pubkeys` with satoshis and profos for BDK wallet.
        let mut output_proofs = Vec::new();
        let mut outputs = Vec::new();

        for output in &self.outputs {
            self.process_output(output, &mut output_proofs, &mut outputs)?;
        }

        let bitcoin_wallet = self.inner_wallet.read().unwrap();
        let mut tx_builder = bitcoin_wallet.build_tx();

        // Do not sort inputs and outputs to make proofs valid
        tx_builder.ordering(TxOrdering::Untouched);
        tx_builder.only_witness_utxo();
        tx_builder.fee_rate(fee_rate);

        if self.is_issuance {
            let announcement = form_issue_announcement(output_proofs.clone())?;

            tx_builder.add_recipient(announcement.to_script(), 0);
        }
        // Fill tx_builder with formed inputs and outputs
        for (script_pubkey, amount) in outputs {
            tx_builder.add_recipient(script_pubkey, amount);
        }
        for (outpoint, psbt_input, weight) in inputs {
            tx_builder.add_foreign_utxo(outpoint, psbt_input, weight)?;
        }

        // Form transaction with satoshi inputs to satisfy conservation rules
        // of Bitcoin.
        let (mut psbt, _details) = tx_builder.finish()?;

        self.insert_empty_receiptproofs(&mut output_proofs, &mut psbt.unsigned_tx.output)?;

        let tx_type = form_tx_type(
            &psbt.unsigned_tx,
            &input_proofs,
            &output_proofs,
            self.is_issuance,
        )?;

        // Sign non LRC20 inputs with BDK wallet.
        bitcoin_wallet.sign(
            &mut psbt,
            SignOptions {
                try_finalize: true,
                trust_witness_utxo: true,
                ..Default::default()
            },
        )?;

        // We need to sign inputs in case of transfer transaction as there are always LRC20 inputs.
        // We also need to sign issue transaction inputs if it spends tweaked satoshis.
        if let Lrc20TxType::Transfer { input_proofs, .. } = &tx_type {
            self.tx_signer.sign(&mut psbt, input_proofs)?;
        } else if let Lrc20TxType::Issue { .. } = &tx_type {
            // Offset is basically the number of regular Bitcoin inputs that we need to skip
            // while constructing input proofs.
            let offset = psbt.inputs.len() - self.inputs.len();
            let input_proofs: ProofMap = input_proofs
                .into_values()
                .enumerate()
                .map(|(index, proof)| ((index + offset) as u32, proof))
                .collect();

            self.tx_signer.sign(&mut psbt, &input_proofs)?;
        }

        let tx = psbt.extract_tx()?;

        Ok(Lrc20Transaction {
            bitcoin_tx: tx,
            tx_type,
        })
    }

    /// Go through inputs, and form list of inputs for BDK wallet, and list of
    /// proofs for each input.
    ///
    /// Also, store keys that will be used for signing.
    async fn process_inputs(
        &mut self,
        ctx: &Secp256k1<All>,
        input_proofs: &mut HashMap<OutPoint, ReceiptProof>,
        inputs: &mut Vec<(OutPoint, psbt::Input, usize)>,
    ) -> eyre::Result<()> {
        #[cfg(feature = "bulletproof")]
        if !self.bulletproof_outputs.is_empty() {
            let outpoints = self
                .bulletproof_outputs
                .keys()
                .copied()
                .collect::<Vec<Option<OutPoint>>>();

            for outpoint in outpoints.into_iter().flatten() {
                self.add_bulletproof_input(outpoint.txid, outpoint.vout);
            }
        }

        for input in &self.inputs {
            let outpoint = input.outpoint();

            // Get proof for that input from synced transactions
            let (proof, output) = self.storage.get_unspent_lrc20_output(outpoint).await?;

            input_proofs.insert(outpoint, proof.clone());

            let mut psbt_input = psbt::Input {
                sighash_type: None,
                witness_utxo: Some(output.clone()),
                ..Default::default()
            };

            // Get descriptor and secret keys depending on the input type
            let (descriptor, secret_keys) =
                self.get_descriptor_and_keys_for_input(ctx, input, &proof)?;

            // Extend list of signers
            self.tx_signer.extend_signers(secret_keys);

            let derived = descriptor.at_derivation_index(0)?;

            psbt_input.update_with_descriptor_unchecked(&derived)?;

            // Some additional processing for psbt input
            if let BuilderInput::Multisig2x2 { .. } = input {
                let ReceiptProof::Multisig(multisig_proof) = &proof else {
                    bail!("Invalid input proof type: proof is not multisig");
                };

                psbt_input.redeem_script = Some(multisig_proof.to_reedem_script()?);
            }
            if let BuilderInput::TaprootReceipt { .. } = input {
                let ReceiptProof::P2TR(taproot_proof) = &proof else {
                    bail!("Invalid input proof type: proof is not taproot");
                };

                psbt_input.witness_script = Some(taproot_proof.to_witness_script()?);
            }

            let weight = derived.max_weight_to_satisfy()?;

            inputs.push((outpoint, psbt_input, weight));
        }

        Ok(())
    }

    /// Return descriptor for input and return map of keys that will be used for
    /// signing input after transaction is built.
    fn get_descriptor_and_keys_for_input(
        &self,
        ctx: &Secp256k1<All>,
        input: &BuilderInput,
        proof: &ReceiptProof,
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
            BuilderInput::Receipt { .. } => {
                let pxh: ReceiptHash = proof.try_into()?;
                let tweaked_pubkey = ReceiptKey::new_with_ctx(pxh, &pubkey1.inner, ctx)?;

                descriptor!(wpkh(tweaked_pubkey.to_public_key()))?
            }
            BuilderInput::TweakedSatoshis { .. } => {
                let tweaked_pubkey =
                    ReceiptKey::new_with_ctx(Receipt::empty(), &pubkey1.inner, ctx)?;

                descriptor!(wpkh(tweaked_pubkey.to_public_key()))?
            }
            BuilderInput::Multisig2x2 {
                second_signer_key, ..
            } => {
                let pubkey2 = second_signer_key.public_key(ctx);
                keys.insert(pubkey2.inner.into(), second_signer_key.inner);

                let (tweaked_key1, key2) =
                    sort_and_tweak(ctx, self.private_key, *second_signer_key, proof)?;

                descriptor!(wsh(multi(2, tweaked_key1.to_public_key(), key2)))?
            }
            BuilderInput::TaprootReceipt { .. } => {
                let pxh: ReceiptHash = proof.try_into()?;
                let (tweaked_xonly_pubkey, _) =
                    ReceiptKey::new_with_ctx(pxh, &pubkey1.inner, ctx)?.x_only_public_key();

                descriptor!(tr(tweaked_xonly_pubkey))?
            }
            BuilderInput::SparkExitScript { .. } => {
                let (tweaked_xonly_pubkey, _) =
                    ReceiptKey::new_with_ctx(proof.receipt(), &pubkey1.inner, ctx)?
                        .x_only_public_key();

                descriptor!(tr(tweaked_xonly_pubkey))?
            }
            #[cfg(feature = "bulletproof")]
            BuilderInput::BulletproofReceipt { .. } => {
                let tweaked_pubkey =
                    ReceiptKey::new_with_ctx(proof.receipt(), &pubkey1.inner, ctx)?;

                descriptor!(wpkh(tweaked_pubkey.to_public_key()))?
            }
        };

        Ok((descriptor, keys))
    }

    /// Add output to the bitcoin transactions and list of output proofs.
    fn process_output(
        &self,
        output: &BuilderOutput,
        output_proofs: &mut Vec<ReceiptProof>,
        outputs: &mut Vec<(ScriptBuf, u64)>,
    ) -> eyre::Result<()> {
        let (script_pubkey, satoshis) = match output {
            // For satoshis output no addtion processing is required
            BuilderOutput::Satoshis {
                satoshis,
                recipient,
            } => {
                let (receipt_proof, script_pubkey) = get_empty_receipt_proof(*recipient)?;

                output_proofs.push(receipt_proof);
                (script_pubkey.clone(), *satoshis)
            }
            // For receipt, form script and push proof of it to the list
            BuilderOutput::Receipt {
                token_pubkey,
                satoshis,
                amount,
                recipient,
                metadata,
            } => {
                let receipt = Receipt::new(*amount, *token_pubkey);
                let receipt_proof = &SigReceiptProof::new(receipt, *recipient, metadata.to_owned());
                let pxh: ReceiptHash = receipt_proof.try_into()?;
                let receipt_key = ReceiptKey::new(pxh, recipient)?;

                let script_pubkey = ScriptBuf::new_p2wpkh(
                    &receipt_key
                        .to_public_key()
                        .wpubkey_hash()
                        .ok_or_eyre("Receipt key is not compressed")?,
                );

                output_proofs.push(receipt_proof.to_owned().into());

                (script_pubkey, *satoshis)
            }
            BuilderOutput::TaprootReceipt {
                token_pubkey,
                satoshis,
                amount,
                recipient,
                metadata,
            } => {
                let receipt = Receipt::new(*amount, *token_pubkey);
                let receipt_proof = &TaprootProof::new(receipt, *recipient, metadata.clone());
                let pxh: ReceiptHash = receipt_proof.try_into()?;
                let receipt_key = ReceiptKey::new(pxh, recipient)?;

                let ctx = Secp256k1::new();
                let script_pubkey = ScriptBuf::new_p2tr(&ctx, receipt_key.to_x_only_pubkey(), None);

                output_proofs.push(receipt_proof.to_owned().into());

                (script_pubkey, *satoshis)
            }
            // For multisig receipt, form script and push proof of it to the list
            BuilderOutput::MultisigReceipt {
                token_pubkey,
                satoshis,
                amount,
                participants,
                required_signatures,
            } => {
                let receipt = Receipt::new(*amount, *token_pubkey);

                let multisig_proof =
                    MultisigReceiptProof::new(receipt, participants.clone(), *required_signatures);
                let script_pubkey = multisig_proof.to_script_pubkey()?;

                output_proofs.push(ReceiptProof::Multisig(multisig_proof));

                (script_pubkey, *satoshis)
            }
            // For bulletproof receipt, form script and push proof of it to the list
            #[cfg(feature = "bulletproof")]
            BuilderOutput::BulletproofReceipt {
                token_pubkey,
                recipient,
                sender,
                token_amount,
                satoshis,
                commitment,
                proof,
                signature,
                token_pubkey_signature,
            } => {
                let receipt = Receipt::new(*token_amount, *token_pubkey);

                let receipt_key = ReceiptKey::new(receipt, &recipient.inner)?;

                let receipt_proof = ReceiptProof::bulletproof(Bulletproof::new(
                    receipt,
                    recipient.inner,
                    sender.inner,
                    *commitment,
                    proof.clone(),
                    *signature,
                    *token_pubkey_signature,
                ));

                let script = ScriptBuf::new_p2wpkh(
                    &PublicKey::from(*receipt_key)
                        .wpubkey_hash()
                        .ok_or_else(|| eyre!("Receipt key is not compressed"))?,
                );

                output_proofs.push(receipt_proof);

                (script, *satoshis)
            }
        };

        outputs.push((script_pubkey, satoshis));

        Ok(())
    }
}

/// Push weighted utxo in case if outpoint's proof is for this token_pubkey.
fn optionally_add_weighted_utxo(
    outpoint: OutPoint,
    proof: ReceiptProof,
    txout: TxOut,
    token_pubkey: TokenPubkey,
    weighted_utxos: &mut Vec<WeightedUtxo>,
) {
    let receipt = proof.receipt();

    #[cfg(feature = "bulletproof")]
    if proof.is_bulletproof() {
        return;
    }

    if receipt.token_pubkey != token_pubkey {
        return;
    }

    let weighted_utxo = new_weighted_utxo(
        outpoint,
        txout,
        receipt,
        matches!(proof, ReceiptProof::SparkExit(_)),
    );
    weighted_utxos.push(weighted_utxo);
}

#[inline]
fn new_weighted_utxo(
    outpoint: OutPoint,
    txout: TxOut,
    receipt: Receipt,
    is_spark: bool,
) -> WeightedUtxo {
    WeightedUtxo {
        satisfaction_weight: 0, // FIXME: calculate weight
        utxo: Utxo::Lrc20(Lrc20Utxo {
            outpoint,
            txout: Lrc20TxOut {
                satoshis: txout.value.to_sat(),
                script_pubkey: txout.script_pubkey,
                receipt,
                is_spark,
            },
            keychain: crate::types::KeychainKind::External,
            is_spent: false,
            derivation_index: 0,
            confirmation_time: None,
        }),
    }
}

pub fn form_issue_announcement(
    output_proofs: Vec<ReceiptProof>,
) -> eyre::Result<IssueAnnouncement> {
    let filtered_proofs = output_proofs
        .iter()
        .filter(|proof| !proof.is_empty_receiptproof())
        .collect::<Vec<&ReceiptProof>>();

    let token_pubkey = filtered_proofs
        .first()
        .map(|proof| proof.receipt().token_pubkey)
        .ok_or_eyre("issuance with no outputs")?;

    #[cfg(feature = "bulletproof")]
    if is_bulletproof(filtered_proofs.clone()) {
        return Ok(IssueAnnouncement {
            token_pubkey,
            amount: 0,
        });
    }

    let outputs_sum = filtered_proofs
        .iter()
        .map(|proof| proof.receipt().token_amount.amount)
        .sum::<u128>();

    Ok(IssueAnnouncement {
        token_pubkey,
        amount: outputs_sum,
    })
}

/// Sort private keys by public keys and tweak first one.
fn sort_and_tweak(
    ctx: &Secp256k1<All>,
    key1: PrivateKey,
    key2: PrivateKey,
    proof: &ReceiptProof,
) -> eyre::Result<(ReceiptKey, PublicKey)> {
    let mut public_key1 = key1.public_key(ctx);
    let mut public_key2 = key2.public_key(ctx);

    if public_key1.inner.serialize()[..] > public_key2.inner.serialize()[..] {
        mem::swap(&mut public_key1, &mut public_key2);
    }

    let key1_tweaked = ReceiptKey::new_with_ctx(proof.receipt(), &public_key1.inner, ctx)?;

    Ok((key1_tweaked, public_key2))
}

/// Generate an empty receipt proof using the given `PublicKey` and an empty `Receipt`.
fn get_empty_receipt_proof(
    recipient: secp256k1::PublicKey,
) -> eyre::Result<(ReceiptProof, ScriptBuf)> {
    let receipt_key = ReceiptKey::new(Receipt::empty(), &recipient)?;

    let pubkey_hash = receipt_key
        .to_public_key()
        .wpubkey_hash()
        .ok_or_eyre("Receipt key is not compressed")?;

    let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey_hash);

    Ok((
        ReceiptProof::EmptyReceipt(EmptyReceiptProof::new(recipient)),
        script_pubkey,
    ))
}

fn form_tx_type(
    unsigned_tx: &Transaction,
    input_proofs: &HashMap<OutPoint, ReceiptProof>,
    output_proofs: &[ReceiptProof],
    is_issuance: bool,
) -> eyre::Result<Lrc20TxType> {
    let mut mapped_input_proofs = BTreeMap::new();

    for (index, input) in unsigned_tx.input.iter().enumerate() {
        let Some(input_proof) = input_proofs.get(&input.previous_output) else {
            continue;
        };

        mapped_input_proofs.insert(index as u32, input_proof.clone());
    }

    let offset = if is_issuance { 1 } else { 0 };
    let output_proofs = output_proofs
        .iter()
        .enumerate()
        .map(|(index, proof)| ((index + offset) as u32, proof.clone()))
        .collect::<BTreeMap<u32, ReceiptProof>>();

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

#[cfg(all(test, feature = "inmemory"))]
mod tests {
    use bdk::database::MemoryDatabase;

    use crate::database::inmemory::SafeInMemoryDB;

    use super::*;

    fn check_is_sync<T: Sync>() {}
    fn check_is_send<T: Send>() {}

    #[test]
    fn test_send_sync() {
        check_is_sync::<TransactionBuilder<SafeInMemoryDB, MemoryDatabase>>();
        check_is_send::<TransactionBuilder<SafeInMemoryDB, MemoryDatabase>>();
    }
}
