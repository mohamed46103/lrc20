use bitcoin::{
    absolute::LockTime,
    hashes::{Hash, sha256::Hash as Sha256Hash},
    secp256k1::{PublicKey, SecretKey},
};

use crate::rpc::v1::{
    SparkLeaf, TokenMintInput, TokenPubkey as ProtoTokenPubkey, TokenTransferInput,
    token_transaction::TokenInput,
};
use crate::rpc::v1::{TokenPubkeyAnnouncement as ProtoTokenPubkeyAnnouncement, TokenPubkeyInfo};
use eyre::OptionExt;
use lrc20_receipts::{Receipt, TokenAmount, TokenPubkey};

use lrc20_types::spark::TokenTransactionStatus;
use lrc20_types::spark::{
    SparkSignature, TokenLeafOutput, TokenLeafToSpend, TokenTransaction, TokenTransactionInput,
    signature::SparkSignatureData, spark_hash::SparkHash,
};
use lrc20_types::spark::{TokensFreezeData, signature::SparkSignatureLeafData};
use lrc20_types::{
    announcements::TokenPubkeyInfo as DomainTokenPubkeyInfo, spark::OperatorSpecificOwnerSignature,
};

pub fn parse_token_transaction(
    token_tx: super::rpc::v1::TokenTransaction,
    user_signatures: Vec<super::rpc::v1::OperatorSpecificOwnerSignature>,
) -> eyre::Result<TokenTransaction> {
    let token_input = token_tx.token_input.ok_or_eyre("Token input is missing")?;

    let parsed_token_input = match token_input {
        crate::rpc::v1::token_transaction::TokenInput::MintInput(issue_input) => {
            let issuer_public_key = PublicKey::from_slice(&issue_input.issuer_public_key)?;
            let issuer_provided_timestamp = issue_input.issuer_provided_timestamp;
            let issuer_signature = match user_signatures.first() {
                Some(user_sig) => {
                    let owner_sig = user_sig
                        .owner_signature
                        .as_ref()
                        .ok_or_eyre("Owner signature is missing")?;
                    let signature = SparkSignature::try_from_slice(&owner_sig.signature)?;
                    let input_index = owner_sig.input_index;
                    let operator_pubkey = user_sig.payload.clone().and_then(|payload| {
                        PublicKey::from_slice(&payload.operator_identity_public_key).ok()
                    });

                    Some(OperatorSpecificOwnerSignature::new(
                        signature,
                        operator_pubkey,
                        Some(input_index),
                    ))
                }
                None => None,
            };

            TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature,
                issuer_provided_timestamp,
            }
        }
        crate::rpc::v1::token_transaction::TokenInput::TransferInput(transfer_input) => {
            let outputs_to_spend = parse_token_leaves_to_spend(transfer_input.outputs_to_spend)?;
            TokenTransactionInput::Transfer { outputs_to_spend }
        }
    };

    let leaves_to_create = parse_token_leaves_to_create(token_tx.token_outputs)?;
    let mut spark_operator_identity_public_keys = Vec::new();
    for pubkey_bytes in token_tx.spark_operator_identity_public_keys {
        let pubkey = PublicKey::from_slice(&pubkey_bytes)?;
        spark_operator_identity_public_keys.push(pubkey);
    }

    Ok(TokenTransaction {
        input: parsed_token_input,
        leaves_to_create,
        spark_operator_identity_public_keys,
        network: Some(token_tx.network as u32),
    })
}

pub fn parse_tokens_freeze_request(
    request: super::rpc::v1::FreezeTokensRequest,
) -> eyre::Result<TokensFreezeData> {
    let payload = request
        .freeze_tokens_payload
        .ok_or_eyre("Freeze tokens payload is missing")?;

    let owner_public_key = PublicKey::from_slice(&payload.owner_public_key)?;
    let operator_identity_public_key =
        PublicKey::from_slice(&payload.operator_identity_public_key)?;
    let token_public_key = TokenPubkey::from_bytes(&payload.token_public_key)?;
    let issuer_signature = SparkSignature::try_from_slice(&request.issuer_signature)?;

    Ok(TokensFreezeData {
        owner_public_key,
        operator_identity_public_key,
        token_public_key,
        should_unfreeze: payload.should_unfreeze,
        issuer_signature,
        timestamp: payload.timestamp,
    })
}

pub fn parse_send_signature_request(
    request: super::rpc::v1::SendSparkSignatureRequest,
) -> eyre::Result<(Vec<SparkSignatureData>, TokenTransaction)> {
    let tx = request
        .final_token_transaction
        .ok_or_eyre("Transaction data is missing")?;

    let token_transaction =
        parse_token_transaction(tx, request.operator_specific_signatures.clone())?;
    let token_transaction_hash = token_transaction.hash();

    let operator_signature_data = request
        .operator_signature_data
        .ok_or_eyre("Missing operator signature")?;
    let operator_signature =
        SparkSignature::try_from_slice(&operator_signature_data.spark_operator_signature)?;

    let operator_pubkey =
        PublicKey::from_slice(&operator_signature_data.operator_identity_public_key)?;
    let mut outputs_to_spend_data = Vec::new();

    for revocation_secret_data in request.revocation_secrets {
        let revocation_secret = SecretKey::from_slice(&revocation_secret_data.revocation_secret)?;

        outputs_to_spend_data.push(SparkSignatureLeafData {
            token_tx_leaf_index: revocation_secret_data.input_index,
            revocation_secret: Some(revocation_secret),
        });
    }

    let signatures = if request.operator_specific_signatures.is_empty() {
        vec![SparkSignatureData::new(
            token_transaction_hash,
            operator_pubkey,
            operator_signature,
            None,
            outputs_to_spend_data,
        )]
    } else {
        request
            .operator_specific_signatures
            .iter()
            .map(|signature_data| {
                let owner_signature_with_index = signature_data
                    .owner_signature
                    .as_ref()
                    .ok_or_eyre("Owner signature is missing")?;

                let owner_signature =
                    SparkSignature::try_from_slice(&owner_signature_with_index.signature)?;

                let input_index = owner_signature_with_index.input_index;

                let identity_pubkey = signature_data.payload.as_ref().and_then(|payload| {
                    PublicKey::from_slice(&payload.operator_identity_public_key).ok()
                });

                let operator_specific_owner_signature = Some(OperatorSpecificOwnerSignature::new(
                    owner_signature,
                    identity_pubkey,
                    Some(input_index),
                ));

                Ok(SparkSignatureData {
                    token_tx_hash: token_transaction_hash,
                    operator_specific_owner_signature,
                    operator_pubkey,
                    operator_signature,
                    outputs_to_spend_data: outputs_to_spend_data.clone(),
                })
            })
            .collect::<Result<Vec<_>, eyre::Error>>()?
    };

    Ok((signatures, token_transaction))
}

pub fn parse_get_spark_tx_request(
    request: super::rpc::v1::GetSparkTxRequest,
) -> eyre::Result<SparkHash> {
    let digest_bytes = request.final_token_transaction_hash;
    let hash = Sha256Hash::from_slice(&digest_bytes)?.into();

    Ok(hash)
}

pub fn parse_token_leaves_to_spend(
    leaves: Vec<super::rpc::v1::TokenOutputToSpend>,
) -> eyre::Result<Vec<TokenLeafToSpend>> {
    let mut result_leaves = Vec::new();

    for leaf in leaves {
        let parent_leaf_hash = Sha256Hash::from_slice(&leaf.prev_token_transaction_hash)?;
        let parent_leaf_index = leaf.prev_token_transaction_vout;

        let leaf_to_spend = TokenLeafToSpend {
            parent_output_hash: parent_leaf_hash,
            parent_output_vout: parent_leaf_index,
        };

        result_leaves.push(leaf_to_spend);
    }

    Ok(result_leaves)
}

pub fn parse_token_leaves_to_create(
    leaves: Vec<super::rpc::v1::TokenOutput>,
) -> eyre::Result<Vec<TokenLeafOutput>> {
    let mut result_leaves = Vec::new();

    for leaf in leaves {
        let id = leaf.id;
        let owner_public_key = PublicKey::from_slice(&leaf.owner_public_key)?;
        let revocation_public_key = PublicKey::from_slice(&leaf.revocation_commitment)?;
        let withdrawal_bond_sats = leaf.withdrawal_bond_sats;
        let withdrawal_locktime = LockTime::from_consensus(leaf.withdrawal_locktime as u32);
        let token_amount_bytes: [u8; 16] = leaf.token_amount.as_slice().try_into()?;
        let token_amount = u128::from_be_bytes(token_amount_bytes);
        let token_amount = TokenAmount::new(token_amount, [0u8; 16]);
        let token_pubkey = TokenPubkey::from_bytes(&leaf.token_public_key)?;
        let receipt = Receipt::new(token_amount, token_pubkey);

        let leaf_to_create = TokenLeafOutput {
            id,
            owner_public_key,
            revocation_public_key,
            withdrawal_bond_sats,
            withdrawal_locktime,
            receipt,
            is_frozen: None,
            withdraw_txid: None,
            withdraw_tx_vout: None,
            withdraw_height: None,
            withdraw_block_hash: None,
        };

        result_leaves.push(leaf_to_create);
    }

    Ok(result_leaves)
}

pub fn into_token_transaction(
    tx: TokenTransaction,
) -> eyre::Result<super::rpc::v1::TokenTransaction> {
    let token_outputs = into_token_outputs_to_create_from_proto(tx.leaves_to_create.clone())?;
    let spark_operator_identity_public_keys = tx
        .spark_operator_identity_public_keys
        .iter()
        .map(|pubkey| pubkey.serialize().to_vec())
        .collect();

    let token_input = Some(into_token_input(tx.clone())?);

    Ok(super::rpc::v1::TokenTransaction {
        token_input,
        token_outputs,
        spark_operator_identity_public_keys,
        network: tx.network.map(|network| network as i32).unwrap_or_default(),
    })
}

pub fn into_token_tx_status(
    status: TokenTransactionStatus,
) -> super::rpc::v1::SparkTransactionStatus {
    match status {
        TokenTransactionStatus::Started => super::rpc::v1::SparkTransactionStatus::Started,
        TokenTransactionStatus::Signed => super::rpc::v1::SparkTransactionStatus::Signed,
        TokenTransactionStatus::Finalized => super::rpc::v1::SparkTransactionStatus::Finalized,
    }
}

pub fn into_token_leaf(
    leaf: &TokenLeafOutput,
    create_tx_hash: Vec<u8>,
    create_tx_vout_index: u32,
) -> eyre::Result<super::rpc::v1::SparkLeaf> {
    let withdrawal_bond_sats = leaf.withdrawal_bond_sats;
    let token_amount = leaf.receipt.token_amount.amount;
    Ok(SparkLeaf {
        token_public_key: leaf.receipt.token_pubkey.to_bytes().to_vec(),
        id: leaf.id.clone(),
        owner_public_key: leaf.owner_public_key.serialize().to_vec(),
        revocation_public_key: leaf.revocation_public_key.serialize().to_vec(),
        withdrawal_bond_sats,
        withdrawal_locktime: leaf.withdrawal_locktime.to_consensus_u32() as u64,
        token_amount: token_amount.to_be_bytes().to_vec(),
        create_tx_hash,
        create_tx_vout_index,
        spend_tx_hash: leaf.withdraw_txid.map(|txid| txid.to_byte_array().to_vec()),
        spend_tx_vout_index: leaf.withdraw_tx_vout,
        is_frozen: leaf.is_frozen,
    })
}

pub fn into_token_outputs_to_create_from_proto(
    outputs: Vec<lrc20_types::spark::TokenLeafOutput>,
) -> eyre::Result<Vec<super::rpc::v1::TokenOutput>> {
    let mut result_outputs = Vec::new();

    for output in outputs {
        let token_amount = output.receipt.token_amount.amount;

        let output_to_create = super::rpc::v1::TokenOutput {
            id: output.id,
            owner_public_key: output.owner_public_key.serialize().to_vec(),
            revocation_commitment: output.revocation_public_key.serialize().to_vec(),
            withdrawal_bond_sats: output.withdrawal_bond_sats,
            withdrawal_locktime: output.withdrawal_locktime.to_consensus_u32() as u64,
            token_public_key: output.receipt.token_pubkey.to_bytes().to_vec(),
            token_amount: token_amount.to_be_bytes().to_vec(),
            is_frozen: output.is_frozen,
        };

        result_outputs.push(output_to_create);
    }

    Ok(result_outputs)
}

pub fn into_token_input(tx: TokenTransaction) -> eyre::Result<TokenInput> {
    let input = match tx.input {
        TokenTransactionInput::Mint {
            issuer_public_key,
            issuer_provided_timestamp,
            ..
        } => TokenInput::MintInput(TokenMintInput {
            issuer_public_key: issuer_public_key.serialize().to_vec(),
            issuer_provided_timestamp,
        }),
        TokenTransactionInput::Transfer { outputs_to_spend } => {
            let proto_leaves = outputs_to_spend
                .into_iter()
                .map(|leaf| super::rpc::v1::TokenOutputToSpend {
                    prev_token_transaction_hash: leaf.parent_output_hash.as_byte_array().to_vec(),
                    prev_token_transaction_vout: leaf.parent_output_vout,
                })
                .collect();

            TokenInput::TransferInput(TokenTransferInput {
                outputs_to_spend: proto_leaves,
            })
        }
    };

    Ok(input)
}

impl From<DomainTokenPubkeyInfo> for TokenPubkeyInfo {
    fn from(info: DomainTokenPubkeyInfo) -> Self {
        TokenPubkeyInfo {
            announcement: info.announcement.map(|a| ProtoTokenPubkeyAnnouncement {
                public_key: Some(ProtoTokenPubkey {
                    public_key: a.token_pubkey.to_bytes().to_vec(),
                }),
                name: a.name,
                symbol: a.symbol,
                decimal: vec![a.decimal],
                max_supply: a.max_supply.to_le_bytes().to_vec(),
                is_freezable: a.is_freezable,
            }),
            total_supply: info.total_supply.to_le_bytes().to_vec(),
            owner: info.owner.map(|s| s.to_bytes()),
            logo_url: info.logo_url,
        }
    }
}
