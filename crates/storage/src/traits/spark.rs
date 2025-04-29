use crate::converters::spark::{
    convert_model_to_spark_output, convert_signature_models_to_spark_signature_data,
    convert_spark_signature_data_to_signature_models, create_output_models_from_token_tx,
    create_spark_model_from_token_tx,
};
use crate::converters::spark::{create_spark_issue_model_from_token_tx, create_token_transaction};

use crate::entities::sea_orm_active_enums::{OperationType, Status};
use bitcoin::hashes::Hash;
use lrc20_types::spark::spark_hash::SparkHash;
use lrc20_types::spark::{TokenTransactionInput, TokenTransactionStatus};
use migration::{NullOrdering, OnConflict};

use crate::PgDatabaseConnectionManager;

use crate::entities::{
    operator_pubkey, operator_signature, spark_issue_data, spark_output, spark_transaction,
    user_signature,
};

use async_trait::async_trait;
use bitcoin::{BlockHash, Txid, secp256k1};

use lrc20_types::spark::signature::{SparkSignatureData, SparkSignatureLeafData};
use lrc20_types::spark::{TokenLeafOutput, TokenTransaction};

use sea_orm::*;

use sea_orm::DbErr;

#[async_trait]
pub trait SparkNodeStorage: PgDatabaseConnectionManager + Send + Sync + 'static {
    async fn get_spark_transaction_model_by_hash(
        &self,
        tx_hash: SparkHash,
    ) -> Result<Option<spark_transaction::Model>, DbErr> {
        spark_transaction::Entity::find()
            .filter(spark_transaction::Column::TxHash.eq(tx_hash.to_byte_array().to_vec()))
            .one(&self.conn().await)
            .await
    }

    async fn get_spark_output_model(
        &self,
        id: String,
    ) -> Result<Option<spark_output::Model>, DbErr> {
        spark_output::Entity::find()
            .filter(spark_output::Column::SparkId.eq(id))
            .one(&self.conn().await)
            .await
    }

    async fn insert_signature_data(&self, signature: SparkSignatureData) -> Result<(), DbErr> {
        let (operator_signature_model, user_signature_model_opt) =
            convert_spark_signature_data_to_signature_models(&signature);

        operator_signature::Entity::insert(operator_signature_model)
            .on_conflict(
                OnConflict::columns([
                    operator_signature::Column::TxHash,
                    operator_signature::Column::OperatorIdentityPubkey,
                ])
                .update_columns([
                    operator_signature::Column::Signature,
                    operator_signature::Column::Type,
                ])
                .to_owned(),
            )
            .exec(&self.conn().await)
            .await?;

        let Some(user_signature_model) = user_signature_model_opt else {
            return Ok(());
        };

        user_signature::Entity::insert(user_signature_model)
            .on_conflict(
                OnConflict::columns([
                    user_signature::Column::TxHash,
                    user_signature::Column::Signature,
                ])
                .update_column(user_signature::Column::OperatorPublicKey)
                .to_owned(),
            )
            .exec(&self.conn().await)
            .await?;

        Ok(())
    }

    async fn set_revocation_secret_key(
        &self,
        tx_hash: SparkHash,
        output_index: u32,
        revocation_secret_key: secp256k1::SecretKey,
    ) -> Result<bool, DbErr> {
        let conn = self.conn().await;

        let Some(token_tx_output) = spark_output::Entity::find()
            .filter(spark_output::Column::TxHash.eq(tx_hash.to_byte_array().to_vec()))
            .filter(spark_output::Column::Vout.eq(output_index as i32))
            .one(&conn)
            .await?
        else {
            return Ok(false);
        };

        let mut token_tx_output_active_model: spark_output::ActiveModel = token_tx_output.into();

        token_tx_output_active_model.revocation_secret_key =
            Set(Some(revocation_secret_key.secret_bytes().to_vec()));

        token_tx_output_active_model.update(&conn).await?;

        Ok(true)
    }

    async fn set_token_transaction_status(
        &self,
        tx_hash: SparkHash,
        status: Status,
    ) -> Result<(), DbErr> {
        spark_transaction::Entity::update_many()
            .filter(spark_transaction::Column::TxHash.eq(tx_hash.to_byte_array().to_vec()))
            .set(spark_transaction::ActiveModel {
                status: Set(status),
                ..Default::default()
            })
            .exec(&self.conn().await)
            .await?;

        Ok(())
    }

    async fn get_token_transaction_status(
        &self,
        tx_hash: SparkHash,
    ) -> Result<TokenTransactionStatus, DbErr> {
        let status = spark_transaction::Entity::find()
            .filter(spark_transaction::Column::TxHash.eq(tx_hash.to_byte_array().to_vec()))
            .select_only()
            .column(spark_transaction::Column::Status)
            .into_tuple()
            .one(&self.conn().await)
            .await?
            .unwrap_or(Status::Started);

        Ok(status.into())
    }

    async fn get_spark_outputs_by_owner_pubkey(
        &self,
        owner_pubkey: &[u8],
    ) -> Result<Vec<TokenLeafOutput>, DbErr> {
        let models = spark_output::Entity::find()
            .filter(spark_output::Column::OwnerPubkey.eq(owner_pubkey.to_vec()))
            .all(&self.conn().await)
            .await?;

        let mut outputs = Vec::new();
        for model in models {
            let output =
                convert_model_to_spark_output(&model).map_err(|e| DbErr::Custom(e.to_string()))?;
            outputs.push(output);
        }

        Ok(outputs)
    }

    async fn udpate_spark_output_freeze_status(
        &self,
        id: String,
        is_frozen: bool,
    ) -> Result<(), DbErr> {
        let mut active_model = spark_output::ActiveModel::new();
        active_model.spark_id = Set(id);
        active_model.is_frozen = Set(Some(is_frozen));
        active_model.update(&self.conn().await).await?;

        Ok(())
    }

    async fn mark_spark_output_as_withdrawn(
        &self,
        id: String,
        txid: Txid,
        vout: i32,
        bloch_hash: BlockHash,
    ) -> Result<(), DbErr> {
        let spark_output = spark_output::Entity::find()
            .filter(spark_output::Column::SparkId.eq(id))
            .one(&self.conn().await)
            .await?
            .ok_or(DbErr::Custom("Spark output not found".to_string()))?;

        let mut active_model: spark_output::ActiveModel = spark_output.into_active_model();
        active_model.withdraw_txid = Set(Some(txid.to_byte_array().to_vec()));
        active_model.withdraw_vout = Set(Some(vout as i32));
        active_model.withdraw_blockhash = Set(Some(bloch_hash.to_byte_array().to_vec()));
        active_model.update(&self.conn().await).await?;

        Ok(())
    }

    async fn insert_spent_output(
        &self,
        db_tx: &DatabaseTransaction,
        txid: SparkHash,
        vout: i32,
        spend_txid: SparkHash,
        spend_vout: i32,
    ) -> Result<(), DbErr> {
        let spark_output = spark_output::Entity::find()
            .filter(spark_output::Column::TxHash.eq(txid.as_byte_array().to_vec()))
            .filter(spark_output::Column::Vout.eq(vout))
            .one(db_tx)
            .await?
            .ok_or(DbErr::Custom("Spark output not found".to_string()))?;

        let mut active_model: spark_output::ActiveModel = spark_output.into_active_model();
        active_model.spend_txid = Set(Some(spend_txid.as_byte_array().to_vec()));
        active_model.spend_vout = Set(Some(spend_vout as i32));
        active_model.update(db_tx).await?;

        Ok(())
    }

    async fn get_spent_output(
        &self,
        txid: SparkHash,
        index: usize,
    ) -> Result<Option<TokenLeafOutput>, DbErr> {
        let spark_output = spark_output::Entity::find()
            .filter(spark_output::Column::SpendTxid.eq(txid.as_byte_array().to_vec()))
            .filter(spark_output::Column::SpendVout.eq(index as i16))
            .one(&self.conn().await)
            .await?;

        let Some(spark_output) = spark_output else {
            return Ok(None);
        };

        let output = convert_model_to_spark_output(&spark_output)
            .map_err(|e| DbErr::Custom(e.to_string()))?;

        Ok(Some(output))
    }

    async fn insert_spark_transaction(&self, token_tx: &TokenTransaction) -> Result<(), DbErr> {
        let tx: DatabaseTransaction = self.tx().await?;

        let tx_model = create_spark_model_from_token_tx(token_tx);
        tx_model.insert(&tx).await?;

        let output_models = create_output_models_from_token_tx(token_tx);
        for model in output_models {
            model.insert(&tx).await?;
        }

        for pubkey in token_tx.spark_operator_identity_public_keys.clone() {
            let operator_pubkey_model = operator_pubkey::ActiveModel {
                tx_hash: Set(token_tx.hash().to_byte_array().to_vec()),
                operator_identity_pubkey: Set(pubkey.serialize().to_vec()),
                id: Default::default(),
            };

            operator_pubkey::Entity::insert(operator_pubkey_model)
                .on_conflict_do_nothing()
                .exec(&tx)
                .await?;
        }

        match &token_tx.input {
            TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature,
                issuer_provided_timestamp,
            } => {
                let issue_model = create_spark_issue_model_from_token_tx(
                    token_tx,
                    issuer_public_key,
                    *issuer_signature,
                    issuer_provided_timestamp,
                )
                .map_err(|e| DbErr::Custom(format!("Failed to create mint input model: {}", e)))?;

                // TODO: move it to another place after fixing
                issue_model.insert(&tx).await?;
            }
            TokenTransactionInput::Transfer { outputs_to_spend } => {
                for (i, leaf) in outputs_to_spend.iter().enumerate() {
                    self.insert_spent_output(
                        &tx,
                        leaf.parent_output_hash.into(),
                        leaf.parent_output_vout as i32,
                        token_tx.hash(),
                        i as i32,
                    )
                    .await?;
                }
            }
        }

        tx.commit().await?;

        Ok(())
    }

    async fn get_spark_tx_with_outputs(
        &self,
        tx_hash: SparkHash,
    ) -> Result<Option<TokenTransaction>, DbErr> {
        let conn = self.conn().await;
        let tx = spark_transaction::Entity::find()
            .filter(spark_transaction::Column::TxHash.eq(tx_hash.as_byte_array().to_vec()))
            .one(&conn)
            .await?;

        let Some(tx) = tx else {
            return Ok(None);
        };

        let operator_pubkeys = tx.find_related(operator_pubkey::Entity).all(&conn).await?;
        let issue_data = tx.find_related(spark_issue_data::Entity).one(&conn).await?;
        let spark_outputs = tx
            .find_related(spark_output::Entity)
            .order_by_asc(spark_output::Column::Vout)
            .all(&conn)
            .await?;
        let spark_inputs = spark_output::Entity::find()
            .filter(spark_output::Column::SpendTxid.eq(tx_hash.as_byte_array().to_vec()))
            .order_by_with_nulls(
                spark_output::Column::SpendVout,
                Order::Asc,
                NullOrdering::Last,
            )
            .all(&conn)
            .await?;

        Ok(create_token_transaction(
            &tx,
            &operator_pubkeys,
            &spark_inputs,
            &spark_outputs,
            issue_data,
        )
        .map_err(|_e| DbErr::Custom("Failed to create token transaction".into()))?)
    }

    async fn get_spark_txs_with_outputs(
        &self,
        tx_hashes: &[SparkHash],
    ) -> Result<Vec<TokenTransaction>, DbErr> {
        let mut txs = Vec::new();
        for tx_hash in tx_hashes {
            let tx = self.get_spark_tx_with_outputs(*tx_hash).await?;
            if let Some(tx) = tx {
                txs.push(tx);
            }
        }
        Ok(txs)
    }

    async fn get_revocation_secret_keys(
        &self,
        tx_hash: SparkHash,
    ) -> Result<Vec<SparkSignatureLeafData>, DbErr> {
        let conn = self.conn().await;

        let token_tx_outputs = spark_output::Entity::find()
            .filter(spark_output::Column::SpendTxid.eq(tx_hash.to_byte_array().to_vec()))
            .all(&conn)
            .await?;

        let signature_data = token_tx_outputs
            .into_iter()
            .filter_map(|output| {
                output.revocation_secret_key.and_then(|bytes| {
                    let revocation_key = secp256k1::SecretKey::from_slice(&bytes)
                        .map_err(|e| DbErr::Custom(format!("Failed to parse secret key: {}", e)))
                        .ok();

                    revocation_key.map(|key| SparkSignatureLeafData {
                        revocation_secret: Some(key),
                        token_tx_leaf_index: output.spend_vout.unwrap_or_default() as u32,
                    })
                })
            })
            .collect();

        Ok(signature_data)
    }

    async fn get_spark_signatures(
        &self,
        tx_hash: SparkHash,
    ) -> Result<Vec<SparkSignatureData>, DbErr> {
        let mut result = Vec::new();

        let operator_signature_models = operator_signature::Entity::find()
            .filter(operator_signature::Column::TxHash.eq(tx_hash.as_byte_array().to_vec()))
            .filter(operator_signature::Column::Signature.is_not_null())
            .all(&self.conn().await)
            .await?;

        let user_signature_models = user_signature::Entity::find()
            .filter(user_signature::Column::TxHash.eq(tx_hash.as_byte_array().to_vec()))
            .all(&self.conn().await)
            .await?;

        let secret_keys = self.get_revocation_secret_keys(tx_hash).await?;

        for (i, user_signature_model) in user_signature_models.iter().enumerate() {
            let Some(operator_signature_model) = operator_signature_models.get(i) else {
                continue;
            };

            let secret_keys = if i == 0 {
                secret_keys.clone()
            } else {
                Vec::new()
            };

            let signature_data = convert_signature_models_to_spark_signature_data(
                operator_signature_model,
                Some(user_signature_model).cloned(),
                secret_keys,
            )
            .map_err(|e| DbErr::Custom(format!("Failed to create signature data: {}", e)))?;

            result.push(signature_data);
        }

        for i in user_signature_models.len()..operator_signature_models.len() {
            let Some(operator_signature_model) = operator_signature_models.get(i) else {
                continue;
            };

            let secret_keys = if result.is_empty() {
                secret_keys.clone()
            } else {
                Vec::new()
            };

            let signature_data = convert_signature_models_to_spark_signature_data(
                operator_signature_model,
                None,
                secret_keys,
            )
            .map_err(|e| DbErr::Custom(format!("Failed to create signature data: {}", e)))?;

            result.push(signature_data);
        }

        Ok(result)
    }

    async fn get_token_transactions_by_page(
        &self,
        page_token: Option<SparkHash>,
        page_size: usize,
        owner_public_key: Option<Vec<u8>>,
        token_public_key: Option<Vec<u8>>,
        operation_types: Vec<i32>,
    ) -> Result<Vec<TokenTransaction>, DbErr> {
        let conn = self.conn().await;

        let mut tx_query =
            spark_transaction::Entity::find().order_by_asc(spark_transaction::Column::TxHash);

        if let Some(token) = page_token {
            tx_query = tx_query
                .filter(spark_transaction::Column::TxHash.gt(token.as_byte_array().to_vec()));
        }

        if !operation_types.is_empty() {
            let mut valid_op_types = Vec::new();
            for op_type_val in operation_types {
                match op_type_val {
                    0 => valid_op_types.push(OperationType::UserTransfer),
                    1 => valid_op_types.push(OperationType::UserBurn),
                    2 => valid_op_types.push(OperationType::IssuerAnnounce),
                    3 => valid_op_types.push(OperationType::IssuerMint),
                    4 => valid_op_types.push(OperationType::IssuerTransfer),
                    5 => valid_op_types.push(OperationType::IssuerFreeze),
                    6 => valid_op_types.push(OperationType::IssuerUnfreeze),
                    7 => valid_op_types.push(OperationType::IssuerBurn),
                    _ => continue,
                }
            }

            if !valid_op_types.is_empty() {
                tx_query =
                    tx_query.filter(spark_transaction::Column::OperationType.is_in(valid_op_types));
            }
        }

        let txs = tx_query.limit(page_size as u64).all(&conn).await?;

        let mut result = Vec::new();

        for tx in txs {
            let tx_hash = tx.tx_hash.clone();

            let mut output_query = spark_output::Entity::find()
                .filter(spark_output::Column::TxHash.eq(tx_hash.clone()))
                .order_by_asc(spark_output::Column::Vout);

            if let Some(owner_key) = &owner_public_key {
                output_query =
                    output_query.filter(spark_output::Column::OwnerPubkey.eq(owner_key.clone()));
            }

            if let Some(token_key) = &token_public_key {
                output_query =
                    output_query.filter(spark_output::Column::TokenPubkey.eq(token_key.clone()));
            }

            let outputs = output_query.all(&conn).await?;

            let inputs = spark_output::Entity::find()
                .filter(spark_output::Column::SpendTxid.eq(tx_hash.clone()))
                .order_by_with_nulls(
                    spark_output::Column::SpendVout,
                    Order::Asc,
                    NullOrdering::Last,
                )
                .all(&conn)
                .await?;

            if (owner_public_key.is_some() || token_public_key.is_some()) && outputs.is_empty() {
                continue;
            }

            let operator_pubkeys = operator_pubkey::Entity::find()
                .filter(operator_pubkey::Column::TxHash.eq(tx_hash.clone()))
                .all(&conn)
                .await?;

            let mut issue_model = None;
            if tx.operation_type == OperationType::IssuerMint {
                issue_model = spark_issue_data::Entity::find()
                    .filter(spark_issue_data::Column::TxHash.eq(tx_hash.clone()))
                    .one(&conn)
                    .await?;
            }

            let token_tx =
                create_token_transaction(&tx, &operator_pubkeys, &inputs, &outputs, issue_model)
                    .map_err(|e| {
                        DbErr::Custom(format!("Failed to create token transaction: {}", e))
                    })?;

            if let Some(token_tx) = token_tx {
                result.push(token_tx);
            }
        }

        if result.len() > page_size {
            result.truncate(page_size + 1);
        }

        Ok(result)
    }

    async fn get_withdrawn_leaves_by_page(
        &self,
        page_token: Option<String>,
        height: Option<i32>,
        page_size: usize,
    ) -> Result<Vec<TokenLeafOutput>, DbErr> {
        let conn = self.conn().await;

        let mut query =
            spark_output::Entity::find().filter(spark_output::Column::WithdrawTxid.is_not_null());

        if let Some(token) = page_token {
            query = query.filter(spark_output::Column::Id.gte(token));
        }

        let outputs = query
            .limit((page_size + 1) as u64)
            .order_by_asc(spark_output::Column::Id)
            .all(&conn)
            .await?;

        let mut results = Vec::new();
        for model in outputs {
            let output =
                convert_model_to_spark_output(&model).map_err(|e| DbErr::Custom(e.to_string()))?;

            if let Some(h) = height {
                if let Some(withdraw_height) = output.withdraw_height {
                    if withdraw_height >= h as u32 {
                        results.push(output);
                    }
                }
            } else {
                results.push(output);
            }
        }

        results.sort_by(|a, b| {
            let height_cmp = a.withdraw_height.cmp(&b.withdraw_height);
            if height_cmp == std::cmp::Ordering::Equal {
                a.id.cmp(&b.id)
            } else {
                height_cmp
            }
        });

        Ok(results)
    }

    async fn get_issue_leaves_by_token_pubkey(
        &self,
        token_pubkey: &[u8],
    ) -> Result<Vec<TokenLeafOutput>, DbErr> {
        let conn = self.conn().await;

        let leaves = spark_output::Entity::find()
            .filter(spark_output::Column::TokenPubkey.eq(token_pubkey.to_vec()))
            .inner_join(spark_transaction::Entity)
            .select_also(spark_transaction::Entity)
            .all(&conn)
            .await?;

        let mut issue_leaves = Vec::new();

        for (leaf, tx) in leaves {
            let Some(tx) = tx else {
                continue;
            };

            if tx.operation_type == OperationType::IssuerMint {
                let token_leaf = convert_model_to_spark_output(&leaf)
                    .map_err(|e| DbErr::Custom(e.to_string()))?;
                issue_leaves.push(token_leaf);
            }
        }

        Ok(issue_leaves)
    }
}
