use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{ecdsa, schnorr};
use bitcoin::{BlockHash, Txid, secp256k1};
use chrono::Utc;
use eyre::OptionExt;
use sea_orm::Set;

use crate::entities::sea_orm_active_enums::SignatureType;
use crate::entities::{
    operator_pubkey::Model as OperatorPubkeyModel,
    operator_signature::{
        ActiveModel as OperatorSignatureActiveModel, Model as OperatorSignatureModel,
    },
    sea_orm_active_enums::{OperationType, Status},
    spark_burn::{ActiveModel as SparkBurnActiveModel, Model as SparkBurnModel},
    spark_freeze_data::{ActiveModel as SparkFreezeDataActiveModel, Model as SparkFreezeDataModel},
    spark_issue_data::{ActiveModel as SparkIssueDataActiveModel, Model as SparkIssueDataModel},
    spark_output::{ActiveModel as SparkOutputActiveModel, Model as SparkOutputModel},
    spark_transaction::{
        ActiveModel as SparkTransactionActiveModel, Model as SparkTransactionModel,
    },
    user_signature::{ActiveModel as UserSignatureActiveModel, Model as UserSignatureModel},
};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use lrc20_receipts::{Receipt, TokenAmount, TokenPubkey};
use lrc20_types::spark::signature::{SparkSignatureData, SparkSignatureLeafData};
use lrc20_types::spark::{
    OperatorSpecificOwnerSignature, SparkSignature, TokenLeafOutput, TokenLeafToSpend,
    TokenTransaction, TokenTransactionInput, TokensFreezeData,
};

impl From<SparkSignature> for SignatureType {
    fn from(signature: SparkSignature) -> Self {
        match signature {
            SparkSignature::ECDSA { .. } => SignatureType::Ecdsa,
            SparkSignature::Schnorr { .. } => SignatureType::Schnorr,
        }
    }
}

pub fn convert_to_spark_transaction_active_model(
    tx_hash: Vec<u8>,
    operation_type: OperationType,
) -> SparkTransactionActiveModel {
    SparkTransactionActiveModel {
        tx_hash: Set(tx_hash),
        operation_type: Set(operation_type),
        status: Set(Status::Started),
        ..Default::default()
    }
}

pub struct SparkBurn {
    pub tx_hash: Vec<u8>,
    pub vout: u16,
    pub token_pubkey: secp256k1::PublicKey,
    pub amount: u128,
}

pub struct UserSignature {
    pub tx_hash: Vec<u8>,
    pub owner_pubkey: secp256k1::PublicKey,
    pub signature: Vec<u8>,
}

pub fn convert_spark_freeze_to_active_model(
    spark_freeze: &TokensFreezeData,
    tx_hash: Vec<u8>,
) -> SparkFreezeDataActiveModel {
    SparkFreezeDataActiveModel {
        tx_hash: Set(tx_hash),
        issuer_pubkey: Set(spark_freeze.owner_public_key.serialize().to_vec()),
        user_pubkey: Set(spark_freeze.token_public_key.to_bytes().to_vec()),
        operator_identity_pubkey: Set(spark_freeze
            .operator_identity_public_key
            .serialize()
            .to_vec()),
        should_unfreeze: Set(spark_freeze.should_unfreeze),
        issuer_signature: Set(spark_freeze.issuer_signature.bytes().to_vec()),
        issuer_provided_timestamp: Set(spark_freeze.timestamp as i64),
        ..Default::default()
    }
}

pub fn convert_model_to_spark_freeze(
    model: &SparkFreezeDataModel,
) -> eyre::Result<TokensFreezeData> {
    let issuer_pubkey = secp256k1::PublicKey::from_slice(&model.issuer_pubkey)?;

    let token_pubkey = TokenPubkey::from_bytes(&model.user_pubkey)?;

    let operator_identity_pubkey =
        secp256k1::PublicKey::from_slice(&model.operator_identity_pubkey)?;

    let signature = SparkSignature::try_from_slice(&model.issuer_signature)?;

    Ok(TokensFreezeData {
        owner_public_key: issuer_pubkey,
        token_public_key: token_pubkey,
        operator_identity_public_key: operator_identity_pubkey,
        should_unfreeze: model.should_unfreeze,
        issuer_signature: signature,
        timestamp: model.issuer_provided_timestamp as u64,
    })
}

pub fn convert_spark_burn_to_active_model(spark_burn: &SparkBurn) -> SparkBurnActiveModel {
    SparkBurnActiveModel {
        tx_hash: Set(spark_burn.tx_hash.clone()),
        vout: Set(spark_burn.vout as i32),
        token_pubkey: Set(spark_burn.token_pubkey.serialize().to_vec()),
        amount: Set(spark_burn.amount.to_string().into_bytes()),
        ..Default::default()
    }
}

pub fn convert_model_to_spark_burn(model: &SparkBurnModel) -> eyre::Result<SparkBurn> {
    let token_pubkey = secp256k1::PublicKey::from_slice(&model.token_pubkey)?;

    let amount = String::from_utf8(model.amount.clone())?.parse::<u128>()?;

    Ok(SparkBurn {
        tx_hash: model.tx_hash.clone(),
        vout: model.vout as u16,
        token_pubkey,
        amount,
    })
}

pub fn convert_spark_signature_data_to_signature_models(
    signature_data: &SparkSignatureData,
) -> (
    OperatorSignatureActiveModel,
    Option<UserSignatureActiveModel>,
) {
    let operator_signature_active_model = OperatorSignatureActiveModel {
        tx_hash: Set(signature_data.token_tx_hash.to_byte_array().to_vec()),
        operator_identity_pubkey: Set(signature_data.operator_pubkey.serialize().to_vec()),
        signature: Set(signature_data.operator_signature.bytes().to_vec()),
        r#type: Set(Some(signature_data.operator_signature.into())),
        ..Default::default()
    };

    let Some(operator_specific_owner_signature) = signature_data.operator_specific_owner_signature
    else {
        return (operator_signature_active_model, None);
    };

    let operator_pubkey = operator_specific_owner_signature
        .operator_identity_public_key
        .map(|pubkey| pubkey.serialize().to_vec());

    let user_signature_active_model = UserSignatureActiveModel {
        tx_hash: Set(signature_data.token_tx_hash.to_byte_array().to_vec()),
        operator_public_key: Set(operator_pubkey),
        signature: Set(operator_specific_owner_signature
            .owner_signature
            .bytes()
            .to_vec()),
        index: Set(operator_specific_owner_signature
            .input_index
            .unwrap_or_default() as i16),
        r#type: Set(Some(
            operator_specific_owner_signature.owner_signature.into(),
        )),
        ..Default::default()
    };

    (
        operator_signature_active_model,
        Some(user_signature_active_model),
    )
}

pub fn convert_signature_models_to_spark_signature_data(
    operator_signature_model: &OperatorSignatureModel,
    user_signature_model: Option<UserSignatureModel>,
    revocation_secrets: Vec<SparkSignatureLeafData>,
) -> eyre::Result<SparkSignatureData> {
    let token_tx_hash = Sha256Hash::from_slice(&operator_signature_model.tx_hash)?.into();
    let operator_pubkey =
        secp256k1::PublicKey::from_slice(&operator_signature_model.operator_identity_pubkey)?;

    let operator_signature = match operator_signature_model.r#type.clone() {
        Some(sig_type) => match sig_type {
            SignatureType::Schnorr => {
                schnorr::Signature::from_slice(&operator_signature_model.signature)?.into()
            }
            SignatureType::Ecdsa => {
                ecdsa::Signature::from_compact(&operator_signature_model.signature)?.into()
            }
        },
        None => SparkSignature::try_from_slice(&operator_signature_model.signature)?,
    };

    let index = user_signature_model
        .clone()
        .map(|user_sig| user_sig.index as u32);
    let operator_specific_owner_signature = match user_signature_model {
        Some(user_signature_model) => {
            let identity_public_key = user_signature_model
                .operator_public_key
                .and_then(|pubkey| secp256k1::PublicKey::from_slice(&pubkey).ok());

            let owner_signature_bytes = user_signature_model.signature;

            let signature = match user_signature_model.r#type.clone() {
                Some(sig_type) => match sig_type {
                    SignatureType::Schnorr => {
                        schnorr::Signature::from_slice(&owner_signature_bytes)?.into()
                    }
                    SignatureType::Ecdsa => {
                        ecdsa::Signature::from_compact(&owner_signature_bytes)?.into()
                    }
                },
                None => SparkSignature::try_from_slice(&owner_signature_bytes)?,
            };
            let input_index = user_signature_model.index as u32;

            Some(OperatorSpecificOwnerSignature::new(
                signature,
                identity_public_key,
                Some(input_index),
            ))
        }
        None => None,
    };

    Ok(SparkSignatureData {
        operator_specific_owner_signature,
        operator_pubkey,
        operator_signature,
        token_tx_hash,
        outputs_to_spend_data: revocation_secrets,
    })
}

pub fn convert_spark_output_to_active_model(
    tx_hash: Vec<u8>,
    vout: u32,
    output: &TokenLeafOutput,
) -> SparkOutputActiveModel {
    SparkOutputActiveModel {
        spark_id: Set(output.id.clone()),
        tx_hash: Set(tx_hash.clone()),
        vout: Set(vout as i32),
        token_pubkey: Set(output.receipt.token_pubkey.to_bytes().to_vec()),
        owner_pubkey: Set(output.owner_public_key.serialize().to_vec()),
        exit_script: Set(None),
        withdrawal_bond_sats: Set(output.withdrawal_bond_sats as i32),
        withdrawal_locktime: Set(output.withdrawal_locktime.to_consensus_u32().to_string()),
        token_amount: Set(output.receipt.token_amount.amount.to_string().into_bytes()),
        revocation_pubkey: Set(output.revocation_public_key.serialize().to_vec()),
        revocation_secret_key: Set(None),
        is_frozen: Set(output.is_frozen),
        withdraw_txid: Set(output
            .withdraw_txid
            .map(|txid| txid.to_byte_array().to_vec())),
        withdraw_vout: Set(output.withdraw_tx_vout.map(|v| v as i32)),
        withdraw_blockhash: Set(output
            .withdraw_block_hash
            .map(|hash| hash.to_byte_array().to_vec())),
        spend_txid: Set(None),
        spend_vout: Set(None),
        ..Default::default()
    }
}

pub fn convert_model_to_spark_output(model: &SparkOutputModel) -> eyre::Result<TokenLeafOutput> {
    let token_pubkey = TokenPubkey::from_bytes(&model.token_pubkey)?;

    let owner_pubkey = secp256k1::PublicKey::from_slice(&model.owner_pubkey)?;

    let revocation_pubkey = secp256k1::PublicKey::from_slice(&model.revocation_pubkey)?;

    let token_amount = String::from_utf8(model.token_amount.clone())?.parse::<u128>()?;

    let withdraw_txid = match &model.withdraw_txid {
        Some(txid) => Some(Txid::from_slice(txid)?),
        None => None,
    };

    let withdraw_block_hash = match &model.withdraw_blockhash {
        Some(hash) => Some(BlockHash::from_slice(hash)?),
        None => None,
    };

    let withdrawal_bond_sats = model.withdrawal_bond_sats as u64;
    let withdrawal_locktime = LockTime::from_consensus(model.withdrawal_locktime.parse::<u32>()?);

    Ok(TokenLeafOutput {
        id: model.spark_id.clone().to_string(),
        owner_public_key: owner_pubkey,
        revocation_public_key: revocation_pubkey,
        withdrawal_bond_sats,
        withdrawal_locktime,
        receipt: Receipt {
            token_pubkey,
            token_amount: TokenAmount::from(token_amount),
        },
        is_frozen: model.is_frozen,
        withdraw_txid,
        withdraw_tx_vout: model.withdraw_vout.map(|v| v as u32),
        withdraw_height: None,
        withdraw_block_hash,
    })
}

pub fn create_token_transaction(
    spark_model: &SparkTransactionModel,
    operator_pubkeys: &[OperatorPubkeyModel],
    input_models: &[SparkOutputModel],
    output_models: &[SparkOutputModel],
    issue_model: Option<SparkIssueDataModel>,
) -> eyre::Result<Option<TokenTransaction>> {
    let leaves_to_create: Vec<TokenLeafOutput> = output_models
        .iter()
        .map(|output| convert_model_to_spark_output(output).unwrap())
        .collect();

    if leaves_to_create.is_empty() {
        return Ok(None);
    }

    let spark_operator_identity_public_keys = operator_pubkeys
        .iter()
        .map(|pubkey_model| {
            secp256k1::PublicKey::from_slice(&pubkey_model.operator_identity_pubkey)
        })
        .collect::<eyre::Result<Vec<_>, _>>()?;

    let input = match spark_model.operation_type {
        OperationType::IssuerMint => {
            let issue_model = issue_model.ok_or_eyre("Missing Spark issue data")?;
            let issuer_public_key = secp256k1::PublicKey::from_slice(&issue_model.issuer_pubkey)?;
            let issuer_signature: SparkSignature = match issue_model
                .signature_type
                .unwrap_or(SignatureType::Ecdsa)
            {
                SignatureType::Schnorr => {
                    secp256k1::schnorr::Signature::from_slice(&issue_model.issuer_signature)?.into()
                }
                SignatureType::Ecdsa => {
                    secp256k1::ecdsa::Signature::from_compact(&issue_model.issuer_signature)?.into()
                }
            };
            let operator_pubkey = issue_model
                .operator_pubkey
                .and_then(|pubkey_bytes| secp256k1::PublicKey::from_slice(&pubkey_bytes).ok());

            TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature: Some(OperatorSpecificOwnerSignature::new(
                    issuer_signature,
                    operator_pubkey,
                    Some(0),
                )),
                issuer_provided_timestamp: issue_model.issuer_provided_timestamp as u64,
            }
        }
        _ => TokenTransactionInput::Transfer {
            outputs_to_spend: input_models
                .iter()
                .filter(|output| output.spend_txid.is_some() && output.spend_vout.is_some())
                .map(|output| TokenLeafToSpend {
                    parent_output_hash: Sha256Hash::from_slice(&output.tx_hash).unwrap(),
                    parent_output_vout: output.vout as u32,
                })
                .collect(),
        },
    };

    Ok(Some(TokenTransaction {
        input,
        leaves_to_create,
        spark_operator_identity_public_keys,
        network: spark_model.network.map(|n| n as u32),
    }))
}

pub fn create_spark_model_from_token_tx(tx: &TokenTransaction) -> SparkTransactionActiveModel {
    SparkTransactionActiveModel {
        tx_hash: Set(tx.hash().as_byte_array().to_vec()),
        operation_type: Set(match &tx.input {
            TokenTransactionInput::Mint { .. } => OperationType::IssuerMint,
            TokenTransactionInput::Transfer { .. } => OperationType::UserTransfer,
        }),
        status: Set(Status::Started),
        network: Set(tx.network.map(|n| n as i32)),
        created_at: Set(Utc::now().timestamp_millis()),
        ..Default::default()
    }
}

pub fn create_output_models_from_token_tx(tx: &TokenTransaction) -> Vec<SparkOutputActiveModel> {
    tx.leaves_to_create
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            convert_spark_output_to_active_model(
                tx.hash().as_byte_array().to_vec(),
                index as u32,
                leaf,
            )
        })
        .collect()
}

pub fn create_spark_issue_model_from_token_tx(
    tx: &TokenTransaction,
    issuer_public_key: &secp256k1::PublicKey,
    issuer_signature: Option<OperatorSpecificOwnerSignature>,
    issuer_provided_timestamp: &u64,
) -> eyre::Result<SparkIssueDataActiveModel> {
    let tx_hash = tx.hash().as_byte_array().to_vec();
    let issuer_pubkey = issuer_public_key;
    let nonce = 0;
    let issue_amount = get_issue_amount(tx);
    let issuer_signature_data = issuer_signature.ok_or_eyre("Missing issuer signature")?;
    Ok(SparkIssueDataActiveModel {
        tx_hash: Set(tx_hash),
        issuer_pubkey: Set(issuer_pubkey.serialize().to_vec()),
        nonce: Set(nonce),
        issuer_signature: Set(issuer_signature_data.owner_signature.bytes().to_vec()),
        operator_pubkey: Set(issuer_signature_data
            .operator_identity_public_key
            .map(|pubkey| pubkey.serialize().to_vec())),
        issue_amount: Set(issue_amount.to_string().into_bytes()),
        issuer_provided_timestamp: Set(*issuer_provided_timestamp as i64),
        signature_type: Set(issuer_signature.map(|sig_data| sig_data.owner_signature.into())),
        ..Default::default()
    })
}

fn get_issue_amount(tx: &TokenTransaction) -> u128 {
    tx.leaves_to_create
        .iter()
        .map(|leaf| leaf.receipt.token_amount.amount)
        .sum()
}

pub fn create_operator_signature_model_from_token_tx(
    tx: &TokenTransaction,
    pubkey: secp256k1::PublicKey,
) -> OperatorSignatureActiveModel {
    OperatorSignatureActiveModel {
        tx_hash: Set(tx.hash().as_byte_array().to_vec()),
        operator_identity_pubkey: Set(pubkey.serialize().to_vec()),
        ..Default::default()
    }
}
