use std::collections::HashMap;

use bdk::{
    SignOptions,
    miniscript::ToPublicKey,
    signer::{InputSigner, SignerContext, SignerWrapper},
};
use bitcoin::{
    PrivateKey, ScriptBuf, TapLeafHash, Witness,
    hashes::Hash,
    key::XOnlyPublicKey,
    psbt::Psbt,
    secp256k1::{self, All, Message, PublicKey, Secp256k1},
    taproot::TapLeaf,
};
use eyre::{OptionExt, bail};
use lrc20_receipts::{
    MultisigReceiptProof, MultisigWitness, P2WPKHWitness, Receipt, ReceiptHash, ReceiptPrivateKey,
    ReceiptProof, SparkExitProof,
};
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

    pub fn sign(self, psbt: &mut Psbt, input_proofs: &ProofMap) -> Result<(), eyre::ErrReport> {
        for (index, proof) in input_proofs {
            match &proof {
                ReceiptProof::Sig(sigproof) => {
                    let pxh: ReceiptHash = sigproof.try_into()?;
                    self.sign_input(pxh, &sigproof.inner_key, psbt, *index)?;
                }
                ReceiptProof::Multisig(multisig_proof) => {
                    self.sign_multiproof_input(multisig_proof, psbt, *index)?;
                }
                ReceiptProof::P2TR(taproot_proof) => {
                    let pxh: ReceiptHash = taproot_proof.try_into()?;
                    self.sign_taproot_input(
                        pxh,
                        &taproot_proof.inner_key.x_only_public_key().0,
                        psbt,
                        *index,
                    )?;
                }
                ReceiptProof::SparkExit(spark_exit_proof) => {
                    self.sign_spark_exit_input(spark_exit_proof, psbt, *index)?;
                }
                #[cfg(feature = "bulletproof")]
                ReceiptProof::Bulletproof(proof) => {
                    self.sign_input(proof.receipt, &proof.inner_key, psbt, *index)?;
                }
                ReceiptProof::EmptyReceipt(proof) => {
                    self.sign_input(Receipt::empty(), &proof.inner_key, psbt, *index)?;
                }
                ReceiptProof::LightningHtlc(_) | ReceiptProof::Lightning(_) => {
                    bail!(
                        r#"HTLC and Lightning inputs cannot be signed using BDK wallet. Only LDK node can
                        spend it, as it has all required information and keys."#
                    )
                }
                ReceiptProof::P2WSH(_) => {
                    bail!("Signing P2WSH inputs is not supported yet.")
                }
            };
        }

        Ok(())
    }

    /// Add witness (signatures, redeem script) for receipt multisig P2WSH input
    /// with tweaked by receipt key.
    fn sign_multiproof_input(
        &self,
        multisig_proof: &MultisigReceiptProof,
        psbt: &mut Psbt,
        index: u32,
    ) -> eyre::Result<()> {
        // clean partial sigs for this input
        psbt.inputs[index as usize].partial_sigs.clear();

        let mut key_pairs = multisig_proof
            .inner_keys
            .iter()
            .filter_map(|key| {
                self.signers
                    .get(&XOnlyPublicKey::from(*key))
                    .cloned()
                    .map(|secret| (secret, *key))
            })
            .collect::<Vec<_>>();

        if key_pairs.len() < multisig_proof.m as usize {
            bail!(
                "Not enough signers for multisig receipt: {} < {}",
                key_pairs.len(),
                multisig_proof.m
            );
        }

        key_pairs.sort_by(|(_, a_pubkey), (_, b_pubkey)| {
            a_pubkey.serialize().cmp(&b_pubkey.serialize())
        });

        let mut secret_keys: Vec<_> = key_pairs
            .into_iter()
            .map(|(secret_key, _)| secret_key)
            .collect();

        // Replace first with one tweaked by receipt to satisfy protocol rules.
        if let Some(first_key) = secret_keys.first_mut() {
            let tweaked =
                ReceiptPrivateKey::new_with_ctx(multisig_proof.receipt, first_key, &self.ctx)?;

            *first_key = tweaked.0;
        }

        for secret_key in secret_keys {
            let signer = SignerWrapper::new(
                PrivateKey::new(secret_key, self.private_key.network),
                SignerContext::Segwitv0,
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
        }

        let signed_input = psbt
            .inputs
            .get_mut(index as usize)
            .expect("Signed input should exist");

        let signatures = signed_input
            .partial_sigs
            .values()
            .cloned()
            .collect::<Vec<_>>();

        let witness = MultisigWitness::new(signatures, multisig_proof.to_reedem_script()?);

        signed_input.final_script_sig = Some(ScriptBuf::new());
        signed_input.final_script_witness = Some(witness.into_witness());

        Ok(())
    }

    fn sign_input(
        &self,
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::PublicKey,
        psbt: &mut Psbt,
        index: u32,
    ) -> Result<(), eyre::ErrReport> {
        // Tweak key with receipt and get public key
        let signing_key = self
            .signers
            .get(&XOnlyPublicKey::from(*inner_key))
            .expect("Singing key for proof should exist");

        let tweaked_key = ReceiptPrivateKey::new_with_ctx(pxh, signing_key, &self.ctx)?;
        let tweaked_pubkey = tweaked_key.0.public_key(&self.ctx).to_public_key();

        // Create a wrapper around private key which can sign transaction inputs.
        let signer = SignerWrapper::new(
            PrivateKey::new(tweaked_key.0, self.private_key.network),
            SignerContext::Segwitv0,
        );

        signer.sign_input(
            psbt,
            index as usize,
            &SignOptions {
                // Do not try to finalize, better to do it by our self as it
                // will always fail.
                try_finalize: false,
                trust_witness_utxo: true,
                ..Default::default()
            },
            &self.ctx,
        )?;

        // Get signed input from psbt
        let signed_input = psbt.inputs.get_mut(index as usize).unwrap();
        let signature = signed_input.partial_sigs.get(&tweaked_pubkey).unwrap();

        // And finalize it with witness data.
        let witness = P2WPKHWitness::new(
            *signature,
            PublicKey::from_slice(&tweaked_pubkey.to_bytes()).unwrap(),
        );

        signed_input.final_script_witness = Some(witness.into());
        signed_input.final_script_sig = Some(ScriptBuf::new());

        Ok(())
    }

    fn sign_taproot_input(
        &self,
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::XOnlyPublicKey,
        psbt: &mut Psbt,
        index: u32,
    ) -> Result<(), eyre::ErrReport> {
        let signing_key = self
            .signers
            .get(inner_key)
            .expect("Singing key for proof should exist");

        let tweaked_key = ReceiptPrivateKey::new_with_ctx(pxh, signing_key, &self.ctx)?;

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

    fn sign_spark_exit_input(
        &self,
        proof: &SparkExitProof,
        psbt: &mut Psbt,
        index: u32,
    ) -> Result<(), eyre::ErrReport> {
        let info = proof.tap_spend_info()?;
        let (script_info, _) = info
            .script_map()
            .iter()
            .next()
            .ok_or_eyre("At least one script path should be present")?;

        let control_block = info
            .control_block(script_info)
            .ok_or_eyre("Control block should be present")?;

        let leaf = TapLeaf::Script(script_info.0.clone(), script_info.1);
        let (leaf_script, _) = leaf.as_script().ok_or_eyre("Leaf script missing")?;
        let leaf_hash = TapLeafHash::from_script(leaf_script, script_info.1);

        let prevouts = psbt
            .inputs
            .iter()
            .map(|input| input.witness_utxo.clone().unwrap())
            .collect::<Vec<_>>();

        let mut sighash_cache = bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
        let cache = sighash_cache.taproot_script_spend_signature_hash(
            index as usize,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            leaf_hash,
            bitcoin::TapSighashType::Default,
        )?;

        let inner_key = proof.script.delay_key.to_x_only_pubkey();
        let signing_key = self
            .signers
            .get(&inner_key)
            .ok_or_eyre("Singing key for proof should exist")?;

        let receipt_key = ReceiptPrivateKey::new(proof.receipt, signing_key)?;

        let signature = self.ctx.sign_schnorr(
            &Message::from_digest_slice(cache.to_raw_hash().as_byte_array())?,
            &receipt_key.keypair(&self.ctx),
        );

        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(script_info.0.as_bytes());
        witness.push(control_block.serialize());

        let input = psbt
            .inputs
            .get_mut(index as usize)
            .ok_or_eyre(format!("No input at index {}", index))?;

        input.final_script_witness = Some(witness);
        input.final_script_sig = Some(ScriptBuf::new());

        Ok(())
    }
}
