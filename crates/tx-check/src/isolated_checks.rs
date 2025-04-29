use std::{collections::HashMap, sync::Arc};

use bitcoin::{
    self, AddressType, ScriptBuf, Transaction, TxIn, TxOut, Witness,
    hashes::sha256::Hash,
    key::Secp256k1,
    secp256k1::{Message, PublicKey, ThirtyTwoByteHash, schnorr},
};
use bitcoin_client::BitcoinRpcApi;

#[cfg(feature = "bulletproof")]
use {
    bitcoin::hashes::{Hash as _, HashEngine, sha256},
    lrc20_receipts::{
        Bulletproof,
        k256::{ProjectivePoint, elliptic_curve::group::GroupEncoding},
    },
    lrc20_types::is_bulletproof,
};

use crate::{errors::CheckError, script_parser::SpendingCondition};
use lrc20_receipts::{
    CheckableProof, P2WPKHWitness, Receipt, ReceiptHash, ReceiptKey, ReceiptProof, TaprootProof,
    TokenPubkey,
};
use lrc20_types::announcements::TransferOwnershipAnnouncement;
use lrc20_types::{Announcement, AnyAnnouncement, ProofMap, announcements::TokenPubkeyInfo};
use lrc20_types::{Lrc20Transaction, Lrc20TxType, announcements::IssueAnnouncement};

/// Checks transactions' correctness in terms of conservation rules and provided proofs.
pub fn check_transaction(lrc20_tx: &Lrc20Transaction) -> Result<(), CheckError> {
    match &lrc20_tx.tx_type {
        Lrc20TxType::Issue {
            output_proofs,
            announcement,
        } => check_issue_isolated(&lrc20_tx.bitcoin_tx, output_proofs, announcement),
        Lrc20TxType::Transfer {
            input_proofs,
            output_proofs,
        } => check_transfer_isolated(&lrc20_tx.bitcoin_tx, input_proofs, output_proofs),
        Lrc20TxType::Announcement(announcement) => check_announcement_isolated(announcement),
        Lrc20TxType::SparkExit { output_proofs } => {
            check_spark_exit_isolated(&lrc20_tx.bitcoin_tx, output_proofs)
        }
    }
}

pub fn check_p2tr_proof(
    prev_output_script: &ScriptBuf,
    taproot_proof: &TaprootProof,
) -> Result<(), CheckError> {
    if !prev_output_script.is_p2tr() {
        return Err(CheckError::ScriptTypeMismatch);
    }

    let pxh: ReceiptHash = taproot_proof
        .try_into()
        .map_err(|_| CheckError::InvalidP2TRProof)?;
    let receipt_key = ReceiptKey::new(pxh, &taproot_proof.inner_key)
        .map_err(|_| CheckError::InvalidReceiptKey)?;

    let expected_script_pub_key =
        ScriptBuf::new_p2tr(&Secp256k1::new(), receipt_key.x_only_public_key().0, None);

    if expected_script_pub_key != *prev_output_script {
        return Err(CheckError::InvalidP2TRProof);
    }

    Ok(())
}

pub(crate) fn check_issue_isolated(
    tx: &Transaction,
    output_proofs_opt: &Option<ProofMap>,
    announcement: &IssueAnnouncement,
) -> Result<(), CheckError> {
    let Some(output_proofs) = output_proofs_opt else {
        return Err(CheckError::NotEnoughProofs {
            provided: 0,
            required: tx.output.len(),
        });
    };

    let announced_amount = check_issue_announcement(tx, announcement)?;
    check_number_of_proofs(tx, output_proofs)?;
    check_same_token_pubkey_proofs(&output_proofs.values().collect::<Vec<_>>(), announcement)?;

    let gathered_outputs = extract_from_iterable_by_proof_map(output_proofs, &tx.output)?;

    for ProofForCheck {
        inner,
        vout,
        statement,
    } in gathered_outputs.iter()
    {
        if statement.script_pubkey.is_op_return() {
            continue;
        }

        inner
            .checked_check_by_output(statement)
            .map_err(|error| CheckError::InvalidProof {
                proof: Box::new((*inner).clone()),
                vout: *vout,
                error,
            })?;
    }

    #[cfg(feature = "bulletproof")]
    if is_bulletproof(output_proofs.values().collect::<Vec<&ReceiptProof>>()) {
        return Ok(());
    }

    let total_amount = output_proofs
        .values()
        .map(|proof| proof.receipt().token_amount.amount)
        .sum::<u128>();

    if total_amount != announced_amount {
        return Err(CheckError::AnnouncedAmountDoesNotMatch(
            announced_amount,
            total_amount,
        ));
    }

    Ok(())
}

fn check_issue_announcement(
    bitcoin_tx: &Transaction,
    provided_announcement: &IssueAnnouncement,
) -> Result<u128, CheckError> {
    for output in bitcoin_tx.output.iter() {
        if let Ok(found_announcement) = IssueAnnouncement::from_script(&output.script_pubkey) {
            if found_announcement.ne(provided_announcement) {
                return Err(CheckError::IssueAnnouncementMismatch);
            }

            return Ok(found_announcement.amount);
        }
    }

    Err(CheckError::IssueAnnouncementNotProvided)
}

pub(crate) fn check_transfer_isolated(
    tx: &Transaction,
    inputs: &ProofMap,
    outputs: &ProofMap,
) -> Result<(), CheckError> {
    check_proofs_isolated(tx, inputs, outputs)?;

    Ok(())
}

pub(crate) fn check_spark_exit_isolated(
    tx: &Transaction,
    outputs: &ProofMap,
) -> Result<(), CheckError> {
    check_number_of_proofs(tx, outputs)?;

    let gathered_outputs = extract_from_iterable_by_proof_map(outputs, &tx.output)?;

    for ProofForCheck {
        inner,
        vout,
        statement,
    } in gathered_outputs.iter()
    {
        if statement.script_pubkey.is_op_return() {
            continue;
        }

        inner
            .checked_check_by_output(statement)
            .map_err(|error| CheckError::InvalidProof {
                proof: Box::new((*inner).clone()),
                vout: *vout,
                error,
            })?;
    }

    Ok(())
}

fn check_number_of_proofs(bitcoin_tx: &Transaction, proofs: &ProofMap) -> Result<(), CheckError> {
    if bitcoin_tx
        .output
        .iter()
        .filter(|proof| !proof.script_pubkey.is_op_return())
        .collect::<Vec<&TxOut>>()
        .len()
        == proofs.len()
    {
        Ok(())
    } else {
        Err(CheckError::NotEnoughProofs {
            provided: proofs.len(),
            required: bitcoin_tx.output.len(),
        })
    }
}

/// Performs an isolated check for a provided announcement.
pub(crate) fn check_announcement_isolated(announcement: &Announcement) -> Result<(), CheckError> {
    // To check transaction's correctness we need to have list of transactions that are frozen
    // except TransferOwnership announcements. So we skip the check for any other announcement
    // type but for TransferOwnership announcement.

    match announcement {
        Announcement::TokenPubkey(_)
        | Announcement::TokenLogo(_)
        | Announcement::TxFreeze(_)
        | Announcement::PubkeyFreeze(_)
        | Announcement::Issue(_) => Ok(()),
        Announcement::TransferOwnership(transfer_ownership) => {
            check_transfer_ownership_announcement(transfer_ownership)
        }
    }
}

/// Checks that the provided transfer ownership announcement is correct.
fn check_transfer_ownership_announcement(
    transfer_ownership: &TransferOwnershipAnnouncement,
) -> Result<(), CheckError> {
    let address_type = script_to_address_type(&transfer_ownership.new_owner);

    // Since ownership transfer cannot be made on P2TR address, we return an error.
    if address_type == AddressType::P2tr {
        return Err(CheckError::NewOwnerP2TRAddress);
    }

    Ok(())
}

pub(crate) struct ProofForCheck<'b, T> {
    /// Statement we will validate (tx input or tx output)
    pub(crate) statement: T,
    /// Number of output in the transaction.
    pub(crate) vout: u32,
    /// Proof we are validating.
    pub(crate) inner: &'b ReceiptProof,
}

impl<'a, T> ProofForCheck<'a, T> {
    pub(crate) fn new(statement: T, vout: u32, proof: &'a ReceiptProof) -> Self {
        Self {
            statement,
            vout,
            inner: proof,
        }
    }
}

/// Generic function for extracting proofs with related to them inputs or
/// outputs.
pub(crate) fn extract_from_iterable_by_proof_map<'a, T>(
    proof_map: &'a ProofMap,
    iterable: &'a [T],
) -> Result<Vec<ProofForCheck<'a, &'a T>>, CheckError> {
    let mut gathered_proofs = Vec::new();

    for (vout, proof) in proof_map {
        let item = iterable
            .get(*vout as usize)
            .ok_or(CheckError::ProofMappedToNotExistingInputOutput)?;

        let proof_for_check = ProofForCheck::new(item, *vout, proof);

        gathered_proofs.push(proof_for_check);
    }

    Ok(gathered_proofs)
}

/// Check that proofs of the transaction do not violate conservation rules. For transfer
/// check that the sum of inputs equals the sum of the outputs.
pub(crate) fn check_conservation_rules(
    inputs: &[ProofForCheck<&TxIn>],
    outputs: &[ProofForCheck<&TxOut>],
) -> Result<(), CheckError> {
    let input_token_pubkeys =
        sum_amount_by_token_pubkey(inputs).ok_or(CheckError::AmountsSumOverflow)?;
    let output_token_pubkeys =
        sum_amount_by_token_pubkey(outputs).ok_or(CheckError::AmountsSumOverflow)?;

    if input_token_pubkeys != output_token_pubkeys {
        return Err(CheckError::ConservationRulesViolated);
    }

    Ok(())
}

fn sum_amount_by_token_pubkey<T>(
    proofs: &[ProofForCheck<T>],
) -> Option<HashMap<TokenPubkey, u128>> {
    let mut token_pubkeys: HashMap<TokenPubkey, u128> = HashMap::new();

    for proof in proofs {
        let receipt = proof.inner.receipt();

        if proof.inner.is_empty_receiptproof() || receipt.token_amount.amount == 0 {
            continue;
        }

        let token_pubkey_sum = token_pubkeys.entry(receipt.token_pubkey).or_insert(0);
        *token_pubkey_sum = token_pubkey_sum.checked_add(receipt.token_amount.amount)?;
    }

    Some(token_pubkeys)
}

/// Check that all the proofs have the same token_pubkey, assuming that all proofs are valid.
fn check_same_token_pubkey_proofs(
    proofs: &[&ReceiptProof],
    announcement: &IssueAnnouncement,
) -> Result<(), CheckError> {
    let filtered_proofs = proofs
        .iter()
        .filter(|proof| !proof.is_empty_receiptproof())
        .copied()
        .collect::<Vec<&ReceiptProof>>();

    let Some(first_proof) = filtered_proofs.first() else {
        return Ok(());
    };

    if first_proof.receipt().token_pubkey != announcement.token_pubkey {
        return Err(CheckError::IssueAnnouncementMismatch);
    }

    if filtered_proofs
        .iter()
        .all(|proof| proof.receipt().token_pubkey == first_proof.receipt().token_pubkey)
    {
        Ok(())
    } else {
        Err(CheckError::NotSameTokenPubkey)
    }
}

fn check_proofs_isolated(
    tx: &Transaction,
    inputs: &ProofMap,
    outputs: &ProofMap,
) -> Result<(), CheckError> {
    check_number_of_proofs(tx, outputs)?;

    let gathered_inputs = extract_from_iterable_by_proof_map(inputs, &tx.input)?;
    let gathered_outputs = extract_from_iterable_by_proof_map(outputs, &tx.output)?;

    for ProofForCheck {
        inner,
        vout,
        statement: txin,
    } in gathered_inputs.iter()
    {
        if inner.is_burn() {
            return Err(CheckError::BurntTokensSpending);
        }

        inner
            .checked_check_by_input(txin)
            .map_err(|error| CheckError::InvalidProof {
                proof: Box::new((*inner).clone()),
                vout: *vout,
                error,
            })?;
    }

    for ProofForCheck {
        inner,
        vout,
        statement: txout,
    } in gathered_outputs.iter()
    {
        inner
            .checked_check_by_output(txout)
            .map_err(|error| CheckError::InvalidProof {
                proof: Box::new((*inner).clone()),
                vout: *vout,
                error,
            })?;
    }

    #[cfg(feature = "bulletproof")]
    if let Some((inputs_bulletproof, outputs_bulletproof)) = extract_bulletproofs(inputs, outputs)?
    {
        return check_bulletproof_conservation_rules(inputs_bulletproof, outputs_bulletproof);
    }

    check_conservation_rules(&gathered_inputs, &gathered_outputs)?;

    Ok(())
}
/// Find owner of the `TokenPubkey` in the inputs.
pub(crate) async fn find_owner_in_txinputs<'a, BC: BitcoinRpcApi + Send + Sync>(
    inputs: &'a [TxIn],
    token_pubkey: &TokenPubkey,
    token_pubkey_info: Option<TokenPubkeyInfo>,
    bitcoin_client: Arc<BC>,
) -> eyre::Result<Option<&'a TxIn>> {
    let owner_script_opt = token_pubkey_info.and_then(|token_pubkey_info| token_pubkey_info.owner);

    for input in inputs {
        // If there is no owner info provided, then it's supposed that the issuer is still
        // the owner of the `TokenPubkey` and has a P2WPKH address.
        let Some(owner_script) = &owner_script_opt else {
            // Handle P2WPKH owner input and check if it spends tweaked satoshis.
            if handle_p2wpkh_input(&input.witness, token_pubkey) {
                return Ok(Some(input));
            }

            continue;
        };

        // Extract scriptPubKey from the witness or scriptSig depending on the transaction type.
        let spending_condition = match script_to_address_type(owner_script) {
            AddressType::P2tr => {
                let prev_out_opt = bitcoin_client
                    .get_tx_out(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                        None,
                    )
                    .await?;

                let Some(prev_out) = prev_out_opt else {
                    continue;
                };

                SpendingCondition::p2tr(&prev_out.script_pub_key.script()?)?
            }
            _ => SpendingCondition::from_txin(input, script_to_address_type(owner_script))?,
        };

        // Compare the extracted script with the owner script.
        if spending_condition.into_script() == *owner_script {
            return Ok(Some(input));
        }
    }

    Ok(None)
}

pub(crate) fn _is_token_tx_signature_valid(
    token_tx_hash: &Hash,
    signature: &schnorr::Signature,
    pubkeys: &[PublicKey],
) -> eyre::Result<bool> {
    let Some(first_key) = pubkeys.first().copied() else {
        return Ok(false);
    };

    let agg_key = pubkeys
        .iter()
        .skip(1)
        .try_fold(first_key, |acc, key| acc.combine(key))?;

    let secp = Secp256k1::verification_only();
    let message = Message::from_digest(token_tx_hash.into_32());
    let verification_result =
        secp.verify_schnorr(signature, &message, &agg_key.x_only_public_key().0);

    Ok(verification_result.is_ok())
}

fn handle_p2wpkh_input(witness: &Witness, token_pubkey: &TokenPubkey) -> bool {
    let Ok(witness) = P2WPKHWitness::from_witness(witness) else {
        return false;
    };

    let witness_public_key = witness.pubkey;
    // It's also necessary to check if the witness pubkey matches the receipt key made with an empty receipt,
    // as the transaction can also spend tweaked UTXOs.
    let receipt_pubkey =
        ReceiptKey::new(Receipt::empty(), token_pubkey.pubkey()).expect("Key should tweak");

    witness_public_key == *token_pubkey.pubkey() || witness_public_key == *receipt_pubkey
}

fn script_to_address_type(script: &ScriptBuf) -> AddressType {
    if script.is_p2pkh() {
        AddressType::P2pkh
    } else if script.is_p2sh() {
        AddressType::P2sh
    } else if script.is_p2wpkh() {
        AddressType::P2wpkh
    } else if script.is_p2wsh() {
        AddressType::P2wsh
    } else {
        AddressType::P2tr
    }
}

#[cfg(feature = "bulletproof")]
type ExtractedBulletproofs = Option<(Vec<Bulletproof>, Vec<Bulletproof>)>;

/// Check that the proofs are bulletproofs and extract them.
#[cfg(feature = "bulletproof")]
fn extract_bulletproofs(
    inputs: &ProofMap,
    outputs: &ProofMap,
) -> Result<ExtractedBulletproofs, CheckError> {
    let mut was_found = false;

    let inputs_bulletproofs = proof_map_to_bulletproofs(&mut was_found, inputs)?;
    let outputs_bulletproofs = proof_map_to_bulletproofs(&mut was_found, outputs)?;

    Ok(match (inputs_bulletproofs, outputs_bulletproofs) {
        (Some(inputs), Some(outputs)) => Some((inputs, outputs)),
        _ => None,
    })
}

#[cfg(feature = "bulletproof")]
fn proof_map_to_bulletproofs(
    was_found: &mut bool,
    proofs: &ProofMap,
) -> Result<Option<Vec<Bulletproof>>, CheckError> {
    proofs
        .values()
        .filter(|proof| !proof.is_empty_receiptproof())
        .map(|receipt_proof| match receipt_proof.get_bulletproof() {
            Some(bulletproof) => {
                *was_found = true;
                Ok(Some(bulletproof.clone()))
            }
            None => {
                if *was_found {
                    Err(CheckError::MixedBulletproofsAndNonBulletproofs)
                } else {
                    Ok(None)
                }
            }
        })
        .collect::<Result<Option<Vec<Bulletproof>>, CheckError>>()
}

#[cfg(feature = "bulletproof")]
fn check_bulletproof_conservation_rules(
    inputs_proofs: Vec<lrc20_receipts::Bulletproof>,
    outputs_proofs: Vec<lrc20_receipts::Bulletproof>,
) -> Result<(), CheckError> {
    // Derive the public key to verify the general signature.

    let general_xonly = derive_pubkey(&inputs_proofs, &outputs_proofs, |_p| true)?;

    let mut engine = sha256::Hash::engine();
    let mut token_pubkey_engines: HashMap<TokenPubkey, sha256::HashEngine> = HashMap::new();
    let mut token_pubkey_xonlys: HashMap<TokenPubkey, bitcoin::key::XOnlyPublicKey> =
        HashMap::new();
    let token_pubkeys = inputs_proofs
        .iter()
        .map(|proof| proof.receipt.token_pubkey)
        .collect::<std::collections::BTreeSet<TokenPubkey>>();

    // Derive the public keys to verify the signatures for each `TokenPubkey`.
    for token_pubkey in token_pubkeys {
        let token_pubkey_xonly = derive_pubkey(&inputs_proofs, &outputs_proofs, |p| {
            p.receipt.token_pubkey == token_pubkey
        })?;

        token_pubkey_xonlys.insert(token_pubkey, token_pubkey_xonly);
    }

    let mut sorted_inputs = inputs_proofs;
    sorted_inputs.sort_by(|a, b| {
        a.receipt
            .token_amount
            .to_bytes()
            .partial_cmp(&b.receipt.token_amount.to_bytes())
            .unwrap()
    });

    for proof in sorted_inputs.iter().chain(outputs_proofs.iter()) {
        engine.input(&proof.receipt.token_amount.to_bytes());

        token_pubkey_engines
            .entry(proof.receipt.token_pubkey)
            .or_default()
            .input(&proof.receipt.token_amount.to_bytes());
    }

    let message = Message::from_hashed_data::<sha256::Hash>(
        sha256::Hash::from_engine(engine).as_byte_array(),
    );
    let messages = token_pubkey_engines
        .into_iter()
        .map(|(token_pubkey, engine)| {
            (
                token_pubkey,
                Message::from_hashed_data::<sha256::Hash>(
                    sha256::Hash::from_engine(engine).as_byte_array(),
                ),
            )
        })
        .collect::<HashMap<TokenPubkey, Message>>();

    for proof in &outputs_proofs {
        verify_signatures(
            proof,
            &token_pubkey_xonlys,
            &messages,
            &message,
            general_xonly,
        )?;
    }

    Ok(())
}

#[cfg(feature = "bulletproof")]
fn verify_signatures(
    proof: &Bulletproof,
    token_pubkey_xonlys: &HashMap<TokenPubkey, bitcoin::key::XOnlyPublicKey>,
    token_pubkey_messages: &HashMap<TokenPubkey, Message>,
    message: &Message,
    general_xonly: bitcoin::key::XOnlyPublicKey,
) -> Result<(), CheckError> {
    let ctx = Secp256k1::new();
    let token_pubkey = proof.receipt.token_pubkey;
    let token_pubkey_xonly = token_pubkey_xonlys
        .get(&token_pubkey)
        .ok_or(CheckError::PublicKeyNotFound)?;

    let token_pubkey_message = token_pubkey_messages
        .get(&token_pubkey)
        .ok_or(CheckError::MessageKeyNotFound)?;

    ctx.verify_schnorr(&proof.signature, message, &general_xonly)
        .map_err(|_e| CheckError::ConservationRulesViolated)?;

    ctx.verify_schnorr(
        &proof.token_pubkey_signature,
        token_pubkey_message,
        token_pubkey_xonly,
    )
    .map_err(|_e| CheckError::ConservationRulesViolated)?;

    Ok(())
}

#[cfg(feature = "bulletproof")]
fn derive_pubkey(
    inputs_proofs: &[Bulletproof],
    outputs_proofs: &[Bulletproof],
    filter: impl Fn(&Bulletproof) -> bool,
) -> Result<bitcoin::key::XOnlyPublicKey, CheckError> {
    let inputs_commitment = combine_commitments(
        ProjectivePoint::default(),
        inputs_proofs,
        &|p1, p2| p1 + p2,
        &filter,
    );

    let pubkey_commitment = combine_commitments(
        inputs_commitment,
        outputs_proofs,
        &|p1, p2| p1 - p2,
        &filter,
    );

    let (xonly, _parity) = PublicKey::from_slice(pubkey_commitment.to_bytes().as_slice())
        .map_err(|_| CheckError::InvalidPublicKey)?
        .x_only_public_key();

    Ok(xonly)
}

#[cfg(feature = "bulletproof")]
fn combine_commitments(
    init_point: ProjectivePoint,
    proofs: &[Bulletproof],
    op: &impl Fn(ProjectivePoint, ProjectivePoint) -> ProjectivePoint,
    filter: &impl Fn(&Bulletproof) -> bool,
) -> ProjectivePoint {
    proofs
        .iter()
        .filter(|proof| filter(proof))
        .fold(init_point, |acc, bulletproof| {
            op(acc, bulletproof.commitment)
        })
}
