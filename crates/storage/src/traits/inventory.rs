use crate::converters::spark::convert_model_to_spark_freeze;
use crate::entities::sea_orm_active_enums::{L1TxStatus, MempoolStatus, Status};

use crate::entities::{l1_transaction, mempool_transaction, spark_freeze_data, spark_transaction};
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use lrc20_types::spark::TokensFreezeData;
use lrc20_types::spark::spark_hash::SparkHash;

use crate::PgDatabaseConnectionManager;

use async_trait::async_trait;

use bitcoin::Txid;
use migration::Query;
use sea_orm::*;

use sea_orm::DbErr;

#[async_trait]
pub trait InventoryStorage: PgDatabaseConnectionManager + Send + Sync + 'static {
    async fn get_lrc20_inventory(&self, inv_size: usize) -> Result<Vec<Txid>, DbErr> {
        let txs = l1_transaction::Entity::find()
            .filter(
                Condition::any()
                    .add(l1_transaction::Column::Status.eq(L1TxStatus::Attached))
                    .add(
                        Condition::all().add(
                            l1_transaction::Column::Txid.in_subquery(
                                Query::select()
                                    .column(mempool_transaction::Column::Txid)
                                    .from(mempool_transaction::Entity)
                                    .and_where(
                                        mempool_transaction::Column::Status
                                            .ne(MempoolStatus::Initialized),
                                    )
                                    .to_owned(),
                            ),
                        ),
                    ),
            )
            .order_by_desc(l1_transaction::Column::Timestamp)
            .limit(inv_size as u64)
            .all(&self.conn().await)
            .await?;

        Ok(txs
            .into_iter()
            .map(|tx| {
                Txid::from_slice(&tx.txid)
                    .map_err(|_e| DbErr::Custom("Invalid txid in database".into()))
            })
            .collect::<Result<Vec<Txid>, DbErr>>()?)
    }

    async fn get_token_txs_inventory(&self, inv_size: usize) -> Result<Vec<SparkHash>, DbErr> {
        let txs = spark_transaction::Entity::find()
            .order_by_desc(spark_transaction::Column::CreatedAt)
            .limit(inv_size as u64)
            .all(&self.conn().await)
            .await?;

        Ok(txs
            .into_iter()
            .map(|tx| {
                Ok(Sha256Hash::from_slice(&tx.tx_hash)
                    .map_err(|_e| DbErr::Custom("Invalid hash in database".into()))?
                    .into())
            })
            .collect::<Result<Vec<SparkHash>, DbErr>>()?)
    }

    async fn get_spark_freezes_inventory(&self) -> Result<Vec<TokensFreezeData>, DbErr> {
        let conn = self.conn().await;

        let freezes = spark_freeze_data::Entity::find()
            .filter(
                Condition::any()
                    .add(
                        spark_freeze_data::Column::TxHash.in_subquery(
                            Query::select()
                                .column(spark_transaction::Column::TxHash)
                                .from(spark_transaction::Entity)
                                .and_where(spark_transaction::Column::Status.eq(Status::Finalized))
                                .to_owned(),
                        ),
                    )
                    .add(
                        spark_freeze_data::Column::TxHash.in_subquery(
                            Query::select()
                                .column(mempool_transaction::Column::Txid)
                                .from(mempool_transaction::Entity)
                                .and_where(
                                    mempool_transaction::Column::Status
                                        .ne(MempoolStatus::Initialized),
                                )
                                .to_owned(),
                        ),
                    ),
            )
            .order_by_desc(spark_freeze_data::Column::IssuerProvidedTimestamp)
            .all(&conn)
            .await?;

        let mut freezes_data = Vec::new();
        for freeze in freezes {
            let freeze_data =
                convert_model_to_spark_freeze(&freeze).map_err(|e| DbErr::Custom(e.to_string()))?;
            freezes_data.push(freeze_data);
        }

        Ok(freezes_data)
    }

    async fn get_spark_inventory(&self) -> Result<Vec<SparkHash>, DbErr> {
        let tx_hashes = spark_transaction::Entity::find()
            .filter(
                Condition::any()
                    .add(spark_transaction::Column::Status.eq(Status::Finalized))
                    .add(
                        Condition::all().add(
                            spark_transaction::Column::TxHash.in_subquery(
                                Query::select()
                                    .column(mempool_transaction::Column::Txid)
                                    .from(mempool_transaction::Entity)
                                    .and_where(
                                        mempool_transaction::Column::Status
                                            .ne(MempoolStatus::Initialized),
                                    )
                                    .to_owned(),
                            ),
                        ),
                    ),
            )
            .order_by_desc(spark_transaction::Column::CreatedAt)
            .all(&self.conn().await)
            .await?;

        let spark_hashes = tx_hashes
            .iter()
            .filter_map(|tx| {
                Sha256Hash::from_slice(&tx.tx_hash)
                    .map(|hash| hash.into())
                    .ok()
            })
            .collect();

        Ok(spark_hashes)
    }
}
