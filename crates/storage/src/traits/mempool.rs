use std::net::SocketAddr;
use std::str::FromStr;

use crate::converters::lrc20::lrc20_transaction_from_model;
use crate::entities::sea_orm_active_enums::MempoolStatus;
use crate::entities::{l1_transaction, mempool_transaction};
use bitcoin::hashes::Hash;

use crate::PgDatabaseConnectionManager;

use async_trait::async_trait;
use bitcoin::Txid;
use lrc20_types::transactions::Lrc20Transaction;
use sea_orm::*;

use sea_orm::DbErr;

#[async_trait]
pub trait MempoolNodeStorage: PgDatabaseConnectionManager + Send + Sync + 'static {
    async fn get_mempool_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<(Lrc20Transaction, MempoolStatus, Option<SocketAddr>)>, DbErr> {
        let conn = self.conn().await;

        let result = mempool_transaction::Entity::find()
            .filter(mempool_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .inner_join(l1_transaction::Entity)
            .select_also(l1_transaction::Entity)
            .one(&conn)
            .await?;

        let Some((mempool_tx, Some(lrc20_tx))) = result else {
            return Ok(None);
        };

        let lrc20_tx = lrc20_transaction_from_model(lrc20_tx)
            .map_err(|_e| DbErr::Custom("Failed to deserialize LRC-20 tx".into()))?;

        let sender = mempool_tx.sender.and_then(|addr| {
            SocketAddr::from_str(&addr)
                .map_err(|e| DbErr::Custom(format!("Invalid sender address: {}", e)))
                .ok()
        });

        Ok(Some((lrc20_tx, mempool_tx.status, sender)))
    }

    async fn get_mempool(
        &self,
    ) -> Result<Vec<(Lrc20Transaction, MempoolStatus, Option<SocketAddr>)>, DbErr> {
        let conn = self.conn().await;

        let results = mempool_transaction::Entity::find()
            .inner_join(l1_transaction::Entity)
            .select_also(l1_transaction::Entity)
            .all(&conn)
            .await?;

        results
            .into_iter()
            .filter_map(|(mempool_tx, lrc20_tx_opt)| {
                let Some(lrc20_tx) = lrc20_tx_opt else {
                    return None;
                };

                let lrc20_tx = match lrc20_transaction_from_model(lrc20_tx) {
                    Ok(tx) => tx,
                    Err(_) => return None,
                };

                let sender = mempool_tx
                    .sender
                    .and_then(|addr| SocketAddr::from_str(&addr).ok());

                Some(Ok((lrc20_tx, mempool_tx.status, sender)))
            })
            .collect()
    }

    async fn get_mempool_by_txids(
        &self,
        txids: Vec<Txid>,
    ) -> Result<Vec<(Lrc20Transaction, MempoolStatus, Option<SocketAddr>)>, DbErr> {
        let conn = self.conn().await;

        let txid_bytes: Vec<Vec<u8>> = txids
            .iter()
            .map(|txid| txid.to_byte_array().to_vec())
            .collect::<Vec<_>>();

        let results = mempool_transaction::Entity::find()
            .filter(mempool_transaction::Column::Txid.is_in(txid_bytes))
            .inner_join(l1_transaction::Entity)
            .select_also(l1_transaction::Entity)
            .all(&conn)
            .await?;

        results
            .into_iter()
            .filter_map(|(mempool_tx, maybe_lrc20_tx)| {
                let Some(lrc20_tx) = maybe_lrc20_tx else {
                    return None;
                };

                let lrc20_tx = match lrc20_transaction_from_model(lrc20_tx) {
                    Ok(tx) => tx,
                    Err(_) => return None,
                };

                let sender = mempool_tx
                    .sender
                    .and_then(|addr| SocketAddr::from_str(&addr).ok());

                Some(Ok((lrc20_tx, mempool_tx.status, sender)))
            })
            .collect()
    }

    async fn put_mempool_transaction(
        &self,
        txid: Txid,
        sender: Option<SocketAddr>,
    ) -> Result<(), DbErr> {
        let conn = self.conn().await;

        let txn = l1_transaction::Entity::find()
            .filter(l1_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&conn)
            .await?;

        let Some(txn) = txn else {
            return Err(DbErr::RecordNotFound(format!(
                "LRC-20 transaction {} is not found",
                txid
            )));
        };

        let mempool_tx_model = mempool_transaction::ActiveModel {
            txid: Set(txid.to_byte_array().to_vec()),
            status: Set(MempoolStatus::Initialized),
            created_at: Set(txn.timestamp),
            sender: Set(sender.map(|sender| sender.to_string())),
            id: Set(txn.id),
        };

        mempool_transaction::Entity::insert(mempool_tx_model)
            .on_conflict_do_nothing()
            .exec(&self.conn().await)
            .await?;

        Ok(())
    }

    async fn update_mempool_tx_status(
        &self,
        txid: Txid,
        status: MempoolStatus,
    ) -> Result<(), DbErr> {
        let Some(mempool_entry) = mempool_transaction::Entity::find()
            .filter(mempool_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&self.conn().await)
            .await?
        else {
            return Err(DbErr::RecordNotFound(format!(
                "Mempool transaction {} is not found",
                txid
            )));
        };

        let mut mempool_active_model: mempool_transaction::ActiveModel = mempool_entry.into();
        mempool_active_model.status = Set(status);
        mempool_active_model.update(&self.conn().await).await?;

        Ok(())
    }

    async fn delete_mempool_entry(&self, txid: Txid) -> Result<(), DbErr> {
        let Some(mempool_entry) = mempool_transaction::Entity::find()
            .filter(mempool_transaction::Column::Txid.eq(txid.to_byte_array().to_vec()))
            .one(&self.conn().await)
            .await?
        else {
            return Ok(());
        };

        mempool_entry.delete(&self.conn().await).await?;

        Ok(())
    }

    async fn delete_mempool_txs(&self, txids: Vec<Txid>) -> Result<(), DbErr> {
        let txid_bytes: Vec<Vec<u8>> = txids
            .into_iter()
            .map(|txid| txid.to_byte_array().to_vec())
            .collect();

        mempool_transaction::Entity::delete_many()
            .filter(mempool_transaction::Column::Txid.is_in(txid_bytes))
            .exec(&self.conn().await)
            .await?;

        Ok(())
    }
}
