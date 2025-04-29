use bdk::miniscript::ToPublicKey;
use bitcoin::{
    OutPoint, Txid,
    hashes::{Hash, HashEngine, sha256},
    secp256k1::{self, All, Secp256k1},
};

use eyre::OptionExt;
use hashbrown::HashMap;
use lrc20_receipts::{
    Bulletproof, TokenPubkey,
    bulletproof_signing::{
        CommitmentResult, create_signatures, get_commitment, tweak_signing_keys,
    },
};

use super::{
    BuilderInput, BuilderOutput, IssuanceTransactionBuilder, TransactionBuilder,
    TransferTransactionBuilder,
};
use crate::txbuilder::WalletStorage;

#[derive(Clone, Copy)]
pub struct BulletproofRecipientParameters {
    pub recipient: secp256k1::PublicKey,
    pub amount: u128,
    pub satoshis: u64,
}

impl<WS, BDB> IssuanceTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Add recipient to the transaction with bulletproof.
    pub fn add_recipient_with_bulletproof(
        &mut self,
        parameters: BulletproofRecipientParameters,
    ) -> eyre::Result<&mut Self> {
        self.tx_builder.add_recipient_with_bulletproof(
            None,
            self.tx_builder.issuance_token_pubkey(),
            parameters,
        )?;

        Ok(self)
    }
}

impl<WS, BDB> TransferTransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Add recipient to the transaction with bulletproof.
    pub fn add_recipient_with_bulletproof(
        &mut self,
        outpoint: OutPoint,
        token_pubkey: TokenPubkey,
        parameters: BulletproofRecipientParameters,
    ) -> eyre::Result<&mut Self> {
        self.0
            .add_recipient_with_bulletproof(Some(outpoint), token_pubkey, parameters)?;

        Ok(self)
    }
}

impl<WS, BDB> TransactionBuilder<WS, BDB>
where
    WS: WalletStorage,
    BDB: bdk::database::BatchDatabase + Clone + Send,
{
    /// Add recipient to the transaction with bulletproof.
    fn add_recipient_with_bulletproof(
        &mut self,
        outpoint: Option<OutPoint>,
        token_pubkey: TokenPubkey,
        params: BulletproofRecipientParameters,
    ) -> eyre::Result<&mut Self> {
        self.manual_selected_only();
        let entry = self.bulletproof_outputs.entry(outpoint).or_default();
        entry.push((token_pubkey, params));

        Ok(self)
    }

    /// Add input to the transaction.
    pub(crate) fn add_bulletproof_input(&mut self, txid: Txid, vout: u32) -> &mut Self {
        let input = BuilderInput::BulletproofReceipt {
            outpoint: OutPoint { txid, vout },
        };

        self.inputs.push(input);

        self
    }

    /// Process `self.bulletproof_outputs` and map them to `self.outputs`.
    ///
    /// This method handles generating Schnorr signatures for the token_amounts.
    pub(crate) fn process_bulletproof_outputs(
        &mut self,
        input_proofs: &HashMap<OutPoint, Bulletproof>,
    ) -> eyre::Result<()> {
        // Init the signing key that will be used to create a Schnorr signature for all the proofs.
        let mut signing_key: Option<secp256k1::SecretKey> = None;
        // Init the signing keys that will be used to create Schnorr signatures for proofs of different token_pubkeys.
        let mut token_pubkey_signing_keys: HashMap<TokenPubkey, secp256k1::SecretKey> =
            HashMap::new();
        // Init the hash engine that will be used to hash all the proofs.
        let mut engine = sha256::Hash::engine();
        // Init the hash engines that will be used to hash the proofs of different token_pubkeys.
        let mut token_pubkey_engines: HashMap<TokenPubkey, sha256::HashEngine> = HashMap::new();
        // Commitments is used to store range proofs, commitments and proof hashes
        // generated using the `bulletproof` crate.
        let mut commitments = Vec::new();
        let network = self.inner_wallet.read().unwrap().network();
        let ctx = Secp256k1::new();
        let sender = self.private_key.public_key(&ctx);

        // Tweak the signing keys that will be used to create Schnorr signatures.
        // If the transaction is an issuance, tweaking will be skipped and dummy signatures will be generated.
        // Note: signatures are not checked for the issuance transactions.
        for (outpoint, params) in self.bulletproof_outputs.clone() {
            // If the outpoint is `Some`, it's a transfer. Else it's an issuance.
            let Some(outpoint) = outpoint else {
                // As the input is `None`, process the issuance and exit the current iteration.
                self.process_bulletproof_issuance(&params, network, sender, &ctx)?;
                continue;
            };

            // If the transaction is a transfer, tweak the general signing key and token_pubkey signing keys
            // with the generated ecdh private keys.
            let bulletproof = input_proofs.get(&outpoint).ok_or_eyre("Input not found")?;
            tweak_signing_keys(
                self.private_key,
                bulletproof,
                network,
                &mut signing_key,
                &mut token_pubkey_signing_keys,
                params
                    .into_iter()
                    .map(|(_, params)| (params.recipient.to_public_key(), params.amount))
                    .collect(),
                &mut commitments,
            )?;
        }

        // If the transaction is an issuance, we don't need to generate Schnorr signatures and can exit at this point.
        if self.is_issuance {
            return Ok(());
        }

        // The next step is to hash the input and output proofs.
        // Proof hashes are consumed by the hashing engine in the following order in case
        // there are K inputs and M outputs: hash(inp[0] || inp[1] || ... || inp[K-1] || outp[0] || outp[1] || ... || outp[M-1]),
        // i.e. the inputs come before the outputs.
        //
        // One important note is that inputs are sorted by proof hashes before hashing.
        let mut mapped_inputs = input_proofs
            .values()
            .map(|proof| {
                (
                    proof.receipt.token_pubkey,
                    proof.receipt.token_amount.to_bytes(),
                )
            })
            .collect::<Vec<(TokenPubkey, [u8; 32])>>();

        // Sort the inputs by proof hashes.
        mapped_inputs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Add inputs proofs to hash engines.
        update_hashes(&mut engine, &mut token_pubkey_engines, mapped_inputs);

        // Add outputs proofs to hash engines.
        update_hashes(
            &mut engine,
            &mut token_pubkey_engines,
            commitments
                .iter()
                .map(|commitment| (commitment.0, commitment.1.proof_hash))
                .collect(),
        );

        // Create signatures and map `self.bulletproof_outputs` to `self.outputs`.
        self.create_bulletproof_outputs(
            &ctx,
            &commitments,
            &signing_key,
            &token_pubkey_signing_keys,
            &engine,
            &token_pubkey_engines,
        )?;

        Ok(())
    }

    /// Create `BulletproofReceipt` builder outputs.
    fn create_bulletproof_outputs(
        &mut self,
        ctx: &Secp256k1<All>,
        commitments: &[(TokenPubkey, CommitmentResult)],
        signing_key: &Option<secp256k1::SecretKey>,
        token_pubkey_signing_keys: &HashMap<TokenPubkey, secp256k1::SecretKey>,
        engine: &sha256::HashEngine,
        token_pubkey_engines: &HashMap<TokenPubkey, sha256::HashEngine>,
    ) -> eyre::Result<()> {
        // Generate the general signature and token_pubkey signatures.
        let (signature, token_pubkey_signatures) = create_signatures(
            ctx,
            signing_key.expect("Key should be some"),
            token_pubkey_signing_keys,
            engine.clone(),
            token_pubkey_engines,
        )?;

        let mut current_commitment = 0;
        for params in self.bulletproof_outputs.values() {
            for (token_pubkey, param) in params {
                let (_, commitment) = &commitments[current_commitment];
                current_commitment += 1;

                self.outputs.push(BuilderOutput::BulletproofReceipt {
                    token_pubkey: *token_pubkey,
                    recipient: param.recipient.to_public_key(),
                    sender: self.private_key.public_key(ctx),
                    token_amount: commitment.proof_hash.into(),
                    satoshis: param.satoshis,
                    commitment: commitment.commitment,
                    proof: commitment.proof.clone(),
                    signature,
                    token_pubkey_signature: *token_pubkey_signatures
                        .get(token_pubkey)
                        .ok_or_eyre("Signature should be present")?,
                })
            }
        }

        Ok(())
    }

    /// Create a bulletproof issuance outpoint with dummy signatures.
    fn process_bulletproof_issuance(
        &mut self,
        params: &Vec<(TokenPubkey, BulletproofRecipientParameters)>,
        network: bitcoin::Network,
        sender: bitcoin::PublicKey,
        ctx: &Secp256k1<All>,
    ) -> eyre::Result<()> {
        for (token_pubkey, param) in params {
            let (
                dh_key,
                CommitmentResult {
                    proof,
                    commitment,
                    proof_hash,
                },
            ) = get_commitment(
                self.private_key,
                param.recipient.to_public_key(),
                network,
                param.amount,
            )?;

            // Create a dummy signature that will not be verified in the tx-checker as it's an issuance.
            let signature = ctx.sign_schnorr(
                &secp256k1::Message::from_hashed_data::<sha256::Hash>(&proof_hash),
                &secp256k1::Keypair::from_secret_key(ctx, &dh_key.inner),
            );

            self.outputs.push(BuilderOutput::BulletproofReceipt {
                token_pubkey: *token_pubkey,
                recipient: param.recipient.to_public_key(),
                sender,
                token_amount: proof_hash.into(),
                satoshis: param.satoshis,
                commitment,
                proof,
                signature,
                token_pubkey_signature: signature,
            });
        }

        Ok(())
    }
}

fn update_hashes(
    engine: &mut sha256::HashEngine,
    token_pubkey_engines: &mut HashMap<TokenPubkey, sha256::HashEngine>,
    proofs: Vec<(TokenPubkey, [u8; 32])>,
) {
    for (token_pubkey, proof_hash) in proofs {
        // Update the general hash engine.
        engine.input(&proof_hash);

        // Update the token_pubkey hash engine.
        token_pubkey_engines
            .entry(token_pubkey)
            .or_default()
            .input(&proof_hash);
    }
}
