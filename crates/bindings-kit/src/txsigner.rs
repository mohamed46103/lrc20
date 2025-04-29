use std::collections::HashMap;

use bdk::{
    SignOptions,
    miniscript::ToPublicKey,
    signer::{InputSigner, SignerContext, SignerWrapper},
};
use bitcoin::{
    PrivateKey, PublicKey, ScriptBuf, Witness,
    key::XOnlyPublicKey,
    psbt::Psbt,
    secp256k1::{self, All, Secp256k1},
};

use eyre::bail;
use lrc20_receipts::{P2WPKHWitness, Receipt, ReceiptPrivateKey, ReceiptProof};
use lrc20_types::ProofMap;

pub struct TransactionSigner {
    /// Secp256k1 engine is used to execute all signature operations.
    ctx: Secp256k1<All>,
    private_key: PrivateKey,

    /// Key-value storage of signers that will participate in transaction
    /// signing. Where key is public key of the signer, and value is private key
    /// of the signer without any tweaking (for both keys).
    signers: HashMap<XOnlyPublicKey, secp256k1::SecretKey>,
}

impl TransactionSigner {
    pub fn new(ctx: Secp256k1<All>, private_key: PrivateKey) -> Self {
        TransactionSigner {
            ctx,
            private_key,
            signers: HashMap::new(),
        }
    }

    pub fn extend_signers(&mut self, signers: HashMap<XOnlyPublicKey, secp256k1::SecretKey>) {
        self.signers.extend(signers);
    }

    pub fn sign(&self, psbt: &mut Psbt, input_proofs: &ProofMap) -> Result<(), eyre::ErrReport> {
        for (index, proof) in input_proofs {
            match &proof {
                ReceiptProof::Sig(sigproof) => {
                    self.sign_input(sigproof.receipt, &sigproof.inner_key, psbt, *index)?;
                }
                ReceiptProof::EmptyReceipt(proof) => {
                    self.sign_input(Receipt::empty(), &proof.inner_key, psbt, *index)?;
                }
                ReceiptProof::P2TR(taproot_proof) => {
                    self.sign_taproot_input(
                        taproot_proof.receipt,
                        &taproot_proof.inner_key.x_only_public_key().0,
                        psbt,
                        *index,
                    )?;
                }
                _ => bail!("Trying to sign an unsupported proof type"),
            };
        }

        Ok(())
    }

    fn sign_input(
        &self,
        receipt: Receipt,
        inner_key: &secp256k1::PublicKey,
        psbt: &mut Psbt,
        index: u32,
    ) -> Result<(), eyre::ErrReport> {
        // Tweak key with receipt and get public key
        let signing_key = self
            .signers
            .get(&XOnlyPublicKey::from(*inner_key))
            .expect("Singing key for proof should exist");

        let tweaked_key = ReceiptPrivateKey::new_with_ctx(receipt, signing_key, &self.ctx)?;
        let tweaked_pubkey = tweaked_key.0.public_key(&self.ctx).to_public_key();

        // Create a wrapper around private key which can sign transaction inputs.
        let signer = SignerWrapper::new(
            PrivateKey::new(tweaked_key.0, self.private_key.network),
            SignerContext::Segwitv0,
        );

        let sign_options = SignOptions {
            // Do not try to finalize, better to do it by our self as it
            // will always fail.
            try_finalize: false,
            trust_witness_utxo: true,
            ..Default::default()
        };

        sign_input(
            &signer,
            psbt,
            index as usize,
            &sign_options,
            &self.ctx,
            &tweaked_pubkey,
        )?;

        Ok(())
    }

    fn sign_taproot_input(
        &self,
        receipt: Receipt,
        inner_key: &secp256k1::XOnlyPublicKey,
        psbt: &mut Psbt,
        index: u32,
    ) -> Result<(), eyre::ErrReport> {
        let signing_key = self
            .signers
            .get(inner_key)
            .expect("Singing key for proof should exist");

        let tweaked_key = ReceiptPrivateKey::new_with_ctx(receipt, signing_key, &self.ctx)?;

        let signer = SignerWrapper::new(
            PrivateKey::new(tweaked_key.0, self.private_key.network),
            SignerContext::Tap {
                is_internal_key: true,
            },
        );

        signer.sign_input(
            psbt,
            index as usize,
            &SignOptions {
                try_finalize: false,
                trust_witness_utxo: true,
                ..Default::default()
            },
            &self.ctx,
        )?;

        let signed_input = psbt.inputs.get_mut(index as usize).unwrap();
        let Some(signature) = signed_input.tap_key_sig else {
            return Ok(());
        };

        let mut witness = Witness::new();
        witness.push(signature.to_vec());

        signed_input.final_script_witness = Some(witness);
        signed_input.final_script_sig = Some(ScriptBuf::new());

        Ok(())
    }
}

pub(crate) fn sign_input(
    signer: &SignerWrapper<PrivateKey>,
    psbt: &mut Psbt,
    index: usize,
    sign_options: &SignOptions,
    ctx: &Secp256k1<All>,
    pubkey: &PublicKey,
) -> eyre::Result<()> {
    signer.sign_input(psbt, index, sign_options, ctx)?;

    let signed_input = psbt.inputs.get_mut(index).unwrap();
    let signature = signed_input.partial_sigs.get(pubkey).unwrap();

    // Finalize the input with the witness data.
    let witness = P2WPKHWitness::new(*signature, pubkey.inner);

    signed_input.final_script_witness = Some(witness.into());
    signed_input.final_script_sig = Some(ScriptBuf::new());

    Ok(())
}
