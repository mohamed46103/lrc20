use std::io::Cursor;

use crate::entities::announcement;
use crate::entities::inner_key;
use crate::entities::issue_announcement;
use crate::entities::l1_transaction;
use crate::entities::lightning_commitment_proof;
use crate::entities::lightning_htlc_proof;
use crate::entities::multisig_proof;
use crate::entities::p2wsh_proof;
use crate::entities::proof;
use crate::entities::pubkey_freeze_announcement;
use crate::entities::sea_orm_active_enums::AnnouncementType;
use crate::entities::sea_orm_active_enums::ProofType;
use crate::entities::sea_orm_active_enums::ScriptType;
use crate::entities::sea_orm_active_enums::{L1TxStatus, L1TxType as L1TxTypeEntity};
use crate::entities::spark_exit_proof;
use crate::entities::token;
use crate::entities::token_logo_announcement;
use crate::entities::token_pubkey_announcement;
use crate::entities::transfer_ownership_announcement;
use crate::entities::tx_freeze_announcement;
use crate::traits::ReceiptProofModel;
use bitcoin::ScriptBuf;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1;
use chrono::Utc;
use lrc20_receipts::{ReceiptProof, TokenPubkey};
use lrc20_types::Announcement;
use lrc20_types::announcements::{
    IssueAnnouncement, TokenLogoAnnouncement, TokenPubkeyAnnouncement,
};
use lrc20_types::{
    ProofMap,
    transactions::{Lrc20Transaction, Lrc20TxType},
};
use sea_orm::Set;
use serde_json;

#[cfg(feature = "bulletproof")]
use {
    crate::entities::bulletproof as bulletproof_entity, k256::elliptic_curve::group::GroupEncoding,
};

type CreateProofResponse = (
    proof::ActiveModel,
    Vec<inner_key::ActiveModel>,
    Vec<token::ActiveModel>,
    Option<ReceiptProofModel>,
);

fn create_inner_key_model(
    txid: Vec<u8>,
    vout: i32,
    pubkey: secp256k1::PublicKey,
) -> inner_key::ActiveModel {
    inner_key::ActiveModel {
        txid: Set(txid),
        vout: Set(vout),
        pubkey: Set(pubkey.serialize().to_vec()),
        ..Default::default()
    }
}

impl From<&Lrc20TxType> for L1TxTypeEntity {
    fn from(tx_type: &Lrc20TxType) -> Self {
        match tx_type {
            Lrc20TxType::Issue { .. } => L1TxTypeEntity::Issue,
            Lrc20TxType::Transfer { .. } => L1TxTypeEntity::Transfer,
            Lrc20TxType::Announcement { .. } => L1TxTypeEntity::Announcement,
            Lrc20TxType::SparkExit { .. } => L1TxTypeEntity::SparkExit,
        }
    }
}

impl From<&ReceiptProof> for ProofType {
    fn from(proof: &ReceiptProof) -> Self {
        match proof {
            ReceiptProof::P2TR(_) => ProofType::P2tr,
            ReceiptProof::P2WSH(_) => ProofType::P2wsh,
            ReceiptProof::Sig(_) => ProofType::P2wpkh,
            ReceiptProof::Multisig(_) => ProofType::Multisig,
            ReceiptProof::LightningHtlc(_) => ProofType::LightningHtlc,
            ReceiptProof::SparkExit(_) => ProofType::SparkExit,
            ReceiptProof::EmptyReceipt(_) => ProofType::Empty,
            ReceiptProof::Lightning(_) => ProofType::Lightning,
            #[cfg(feature = "bulletproof")]
            ReceiptProof::Bulletproof(_) => ProofType::Bulletproof,
        }
    }
}

impl From<ScriptBuf> for ScriptType {
    fn from(script: ScriptBuf) -> Self {
        if script.is_p2tr() {
            ScriptType::P2tr
        } else if script.is_p2wsh() {
            ScriptType::P2wsh
        } else if script.is_p2wpkh() {
            ScriptType::P2wpkh
        } else {
            ScriptType::P2tr
        }
    }
}

pub fn create_lrc20_transaction_model(
    tx: &Lrc20Transaction,
    status: L1TxStatus,
) -> l1_transaction::ActiveModel {
    l1_transaction::ActiveModel {
        txid: Set(tx.bitcoin_tx.txid().to_byte_array().to_vec()),
        raw_tx: Set({
            let mut bytes = Vec::new();
            tx.consensus_encode(&mut bytes).unwrap();
            bytes
        }),
        timestamp: Set(Utc::now().timestamp_millis()),
        block_number: Set(0),
        block_hash: Set(vec![]),
        status: Set(status),
        tx_type: Set((&tx.tx_type).into()),
        ..Default::default()
    }
}

pub(crate) fn lrc20_transaction_from_model(
    l1_tx_model: l1_transaction::Model,
) -> eyre::Result<Lrc20Transaction> {
    let mut raw_tx = Cursor::new(l1_tx_model.raw_tx);
    let lrc20_tx = Decodable::consensus_decode(&mut raw_tx)?;

    Ok(lrc20_tx)
}

pub(crate) fn create_proof_models(
    bitcoin_tx: &Transaction,
    proof_map: ProofMap,
) -> Vec<CreateProofResponse> {
    let txid = bitcoin_tx.txid().to_byte_array().to_vec();
    proof_map
        .iter()
        .map(|(vout, receipt_proof)| {
            let vout = *vout as i32;
            let proof = proof::ActiveModel {
                txid: Set(txid.clone()),
                vout: Set(vout),
                spend_txid: Set(None),
                spend_vout: Set(None),
                is_frozen: Set(false),
                script: Set(bitcoin_tx.output[vout as usize]
                    .script_pubkey
                    .to_bytes()
                    .to_vec()),
                script_type: Set(bitcoin_tx.output[vout as usize]
                    .script_pubkey
                    .clone()
                    .into()),
                metadata: Set(receipt_proof
                    .metadata()
                    .map(|metadata| serde_json::to_vec(&metadata).unwrap_or_default())),
                proof_type: Set(receipt_proof.into()),
                ..Default::default()
            };

            let receipt = receipt_proof.receipt();
            let tokens = vec![token::ActiveModel {
                txid: Set(txid.clone()),
                vout: Set(vout),
                token_pubkey: Set(receipt.token_pubkey.to_bytes().to_vec()),
                token_amount: Set(receipt.token_amount.to_bytes().to_vec()),
                ..Default::default()
            }];

            let mut inner_keys = Vec::new();

            let proof_model = match receipt_proof {
                ReceiptProof::EmptyReceipt(empty_receipt_proof) => {
                    inner_keys.push(create_inner_key_model(
                        txid.clone(),
                        vout,
                        empty_receipt_proof.inner_key,
                    ));

                    None
                }
                ReceiptProof::Sig(p2_wpkhproof) => {
                    inner_keys.push(create_inner_key_model(
                        txid.clone(),
                        vout,
                        p2_wpkhproof.inner_key,
                    ));

                    None
                }
                ReceiptProof::Multisig(multisig_receipt_proof) => {
                    inner_keys.extend(
                        multisig_receipt_proof
                            .inner_keys
                            .iter()
                            .map(|inner_key| create_inner_key_model(
                                txid.clone(),
                                vout,
                                *inner_key,
                            ))
                            .collect::<Vec<_>>(),
                    );

                    Some(ReceiptProofModel::Multisig(multisig_proof::ActiveModel {
                        txid: Set(txid.clone()),
                        vout: Set(vout),
                        m: Set(multisig_receipt_proof.m as i32),
                        ..Default::default()
                    }))
                }
                ReceiptProof::Lightning(lightning_commitment_proof) => {
                    Some(ReceiptProofModel::LightningCommitment(
                        lightning_commitment_proof::ActiveModel {
                            txid: Set(txid.clone()),
                            vout: Set(vout),
                            revocation_pubkey: Set(lightning_commitment_proof
                                .data
                                .revocation_pubkey
                                .serialize()
                                .to_vec()),
                            local_delayed_pubkey: Set(lightning_commitment_proof
                                .data
                                .local_delayed_pubkey
                                .serialize()
                                .to_vec()),
                            to_self_delay: Set(lightning_commitment_proof.data.to_self_delay as i32),
                            ..Default::default()
                        },
                    ))
                }
                ReceiptProof::LightningHtlc(lightning_htlc_proof) => {
                    Some(ReceiptProofModel::LightningHtlc(lightning_htlc_proof::ActiveModel {
                        txid: Set(txid.clone()),
                        vout: Set(vout),
                        cltv_expiry: Set(match lightning_htlc_proof.data.kind {
                            lrc20_receipts::HtlcScriptKind::Offered => None,
                            lrc20_receipts::HtlcScriptKind::Received { cltv_expiry } => Some(cltv_expiry as i32),
                        }),
                        local_htlc_key: Set(lightning_htlc_proof.data.local_htlc_key.serialize().to_vec()),
                        payment_hash: Set(lightning_htlc_proof.data.payment_hash.to_byte_array().to_vec()),
                        remote_htlc_key: Set(lightning_htlc_proof.data.remote_htlc_key.serialize().to_vec()),
                        revocation_key_hash: Set(lightning_htlc_proof.data.revocation_key_hash.to_byte_array().to_vec()),
                        ..Default::default()
                    }))
                },
                ReceiptProof::P2WSH(p2_wshproof) => {
                    inner_keys.push(create_inner_key_model(
                        txid.clone(),
                        vout,
                        p2_wshproof.inner_key,
                    ));

                    Some(ReceiptProofModel::P2WSH(p2wsh_proof::ActiveModel {
                        txid: Set(txid.clone()),
                        vout: Set(vout),
                        script: Set(p2_wshproof.script.clone().into_bytes()),
                        ..Default::default()
                    }))
                },
                ReceiptProof::P2TR(taproot_proof) => {
                    inner_keys.push(create_inner_key_model(
                        txid.clone(),
                        vout,
                        taproot_proof.inner_key,
                    ));

                    None
                },
                ReceiptProof::SparkExit(spark_exit_proof) => {
                    Some(ReceiptProofModel::SparkExit(spark_exit_proof::ActiveModel {
                        txid: Set(txid.clone()),
                        vout: Set(vout),
                        delay_key: Set(spark_exit_proof.script.delay_key.serialize().to_vec()),
                        revocation_key: Set(spark_exit_proof.script.revocation_key.serialize().to_vec()),
                        locktime: Set(spark_exit_proof.script.locktime as i32),
                        ..Default::default()
                    }))
                },
                #[cfg(feature = "bulletproof")]
                ReceiptProof::Bulletproof(bulletproof) => {
                    Some(ReceiptProofModel::Bulletproof(bulletproof_entity::ActiveModel {
                        txid: Set(txid.clone()),
                        vout: Set(vout),
                        sender_key: Set(bulletproof.sender_key.serialize().to_vec()),
                        commitment: Set(bulletproof.commitment.to_bytes().to_vec()),
                        proof: Set(bulletproof.proof.to_bytes()),
                        signature: Set(bulletproof.signature.serialize().to_vec()),
                        token_pubkey_signature: Set(bulletproof.token_pubkey_signature.serialize().to_vec()),
                    }))
                },
            };

            (proof, inner_keys, tokens, proof_model)
        })
        .collect()
}

pub fn create_pubkey_freeze_announcement_model(
    txid: Vec<u8>,
    freeze_pubkey: TokenPubkey,
) -> pubkey_freeze_announcement::ActiveModel {
    pubkey_freeze_announcement::ActiveModel {
        txid: Set(txid.clone()),
        freeze_pubkey: Set(freeze_pubkey.to_bytes().to_vec()),
        ..Default::default()
    }
}

pub fn create_tx_freeze_announcement_model(
    txid: Vec<u8>,
    freeze_txid: Vec<u8>,
    freeze_vout: u32,
) -> tx_freeze_announcement::ActiveModel {
    tx_freeze_announcement::ActiveModel {
        txid: Set(txid.clone()),
        freeze_txid: Set(freeze_txid.clone()),
        freeze_vout: Set(freeze_vout as i32),
        ..Default::default()
    }
}

pub fn create_token_pubkey_announcement_model(
    txid: Vec<u8>,
    token_pubkey_announcement: TokenPubkeyAnnouncement,
) -> token_pubkey_announcement::ActiveModel {
    token_pubkey_announcement::ActiveModel {
        txid: Set(txid.clone()),
        name: Set(token_pubkey_announcement.name),
        symbol: Set(token_pubkey_announcement.symbol),
        decimal: Set(token_pubkey_announcement.decimal as i32),
        max_supply: Set(token_pubkey_announcement.max_supply.to_be_bytes().to_vec()),
        is_freezable: Set(token_pubkey_announcement.is_freezable),
        ..Default::default()
    }
}

pub fn create_transfer_ownership_announcement_model(
    txid: Vec<u8>,
    new_owner_script: ScriptBuf,
) -> transfer_ownership_announcement::ActiveModel {
    transfer_ownership_announcement::ActiveModel {
        txid: Set(txid.clone()),
        new_owner: Set(new_owner_script.to_bytes().to_vec()),
        ..Default::default()
    }
}

pub fn create_logo_announcement_model(
    txid: Vec<u8>,
    announcement: TokenLogoAnnouncement,
) -> token_logo_announcement::ActiveModel {
    token_logo_announcement::ActiveModel {
        txid: Set(txid.clone()),
        logo_url: Set(announcement.logo_url),
        ..Default::default()
    }
}

pub fn create_issue_announcement_model(
    txid: Vec<u8>,
    announcement: IssueAnnouncement,
) -> issue_announcement::ActiveModel {
    issue_announcement::ActiveModel {
        txid: Set(txid.clone()),
        amount: Set(announcement.amount.to_be_bytes().to_vec()),
        ..Default::default()
    }
}

pub fn get_pubkey(announcement: &Announcement) -> TokenPubkey {
    match announcement {
        Announcement::TokenPubkey(announcement) => announcement.token_pubkey,
        Announcement::TokenLogo(announcement) => announcement.token_pubkey,
        Announcement::Issue(announcement) => announcement.token_pubkey,
        Announcement::TransferOwnership(announcement) => announcement.token_pubkey,
        Announcement::TxFreeze(announcement) => announcement.token_pubkey,
        Announcement::PubkeyFreeze(announcement) => announcement.token_pubkey,
    }
}

pub fn create_announcement_model(
    txid: Vec<u8>,
    announcement: Announcement,
) -> announcement::ActiveModel {
    let announcement_type = match announcement {
        Announcement::TokenPubkey(_) => AnnouncementType::TokenPubkey,
        Announcement::TokenLogo(_) => AnnouncementType::TokenLogo,
        Announcement::Issue(_) => AnnouncementType::Issue,
        Announcement::TransferOwnership(_) => AnnouncementType::TransferOwnership,
        Announcement::TxFreeze(_) => AnnouncementType::TxFreeze,
        Announcement::PubkeyFreeze(_) => AnnouncementType::PubkeyFreeze,
    };

    announcement::ActiveModel {
        txid: Set(txid.clone()),
        token_pubkey: Set(get_pubkey(&announcement).to_bytes().to_vec()),
        r#type: Set(announcement_type),
        ..Default::default()
    }
}

pub fn create_proof_pubkeys_model(
    txid: Vec<u8>,
    proof_map: ProofMap,
) -> Vec<inner_key::ActiveModel> {
    let bitcoin_tx = Transaction::consensus_decode(&mut &txid[..]).unwrap();
    proof_map
        .keys()
        .map(|vout| inner_key::ActiveModel {
            txid: Set(txid.clone()),
            vout: Set(*vout as i32),
            pubkey: Set(bitcoin_tx.output[*vout as usize]
                .script_pubkey
                .to_bytes()
                .to_vec()),
            ..Default::default()
        })
        .collect()
}

pub(crate) fn convert_from_token_pubkey_announcement_model_to_announcement(
    model: &token_pubkey_announcement::Model,
    announcement: &announcement::Model,
) -> TokenPubkeyAnnouncement {
    TokenPubkeyAnnouncement {
        token_pubkey: TokenPubkey::from_bytes(&announcement.token_pubkey).unwrap(),
        name: model.name.clone(),
        symbol: model.symbol.clone(),
        decimal: model.decimal as u8,
        max_supply: u128::from_be_bytes(model.max_supply.clone().try_into().unwrap()),
        is_freezable: model.is_freezable,
    }
}

pub(crate) fn convert_from_issue_announcement_model_to_announcement(
    model: &issue_announcement::Model,
    announcement: &announcement::Model,
) -> IssueAnnouncement {
    IssueAnnouncement {
        token_pubkey: TokenPubkey::from_bytes(&announcement.token_pubkey).unwrap(),
        amount: u128::from_be_bytes(model.amount.clone().try_into().unwrap()),
    }
}
