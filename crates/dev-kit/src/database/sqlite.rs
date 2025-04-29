use std::fs::File;
use std::path::Path;
use std::{path::PathBuf, str::FromStr};

use bitcoin::OutPoint;
use bitcoin::TxOut;
use bitcoin::Txid;
use eyre::{Context, OptionExt};
use futures::TryFutureExt;
use futures::TryStreamExt;
use jsonrpsee::core::async_trait;
use lrc20_receipts::ReceiptProof;
use sqlx::sqlite::SqlitePool;
use sqlx::types::Json;

use crate::database::Lrc20OutputsStorage;

use self::migrator::MIGRATOR;

use super::StorageStream;
use super::{KeyValueStorage, Lrc20OutputState};

mod migrator;

pub const DB_FILE_NAME: &str = "db.sqlite";

#[derive(Clone)]
pub struct DB {
    pool: SqlitePool,
}

pub struct Config {
    /// Path to the SQLite database file
    pub path: PathBuf,
}

impl Config {
    pub fn to_url(&self) -> String {
        let db_file_path = self.to_path();

        format!("sqlite://{}", db_file_path.display())
    }

    fn to_path(&self) -> PathBuf {
        self.path.join(DB_FILE_NAME)
    }
}

impl DB {
    pub async fn new(config: Config) -> eyre::Result<Self> {
        let db_url = config.to_url();
        let db_path = config.to_path();

        Self::init_dir(db_path)?;

        let pool = SqlitePool::connect(&db_url).await?;

        MIGRATOR.run(&pool).await?;

        Ok(Self { pool })
    }

    fn init_dir(path: impl AsRef<Path>) -> eyre::Result<()> {
        let path = path.as_ref();
        let dir = path
            .parent()
            .ok_or_eyre("Invalid path to storage provided")?;

        // ensure that all directories to path exist
        std::fs::create_dir_all(dir)?;

        // ensure db file is created
        if !path.exists() {
            File::create(path)?;
        }

        Ok(())
    }
}

#[async_trait]
impl Lrc20OutputsStorage for DB {
    /// Get the unspent lrc20 outpoint for the given outpoint
    async fn try_get_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
    ) -> eyre::Result<Option<(ReceiptProof, TxOut)>> {
        #[derive(sqlx::FromRow)]
        struct UnspentLrc20OutpointRow {
            proof: Json<ReceiptProof>,
            txout: Json<TxOut>,
        }

        let txid = outpoint.txid.to_string();

        let row_opt = sqlx::query_as::<_, UnspentLrc20OutpointRow>(
            r#"
            SELECT proof, txout
            FROM lrc20_outputs
            WHERE txid = ? AND vout = ?
            "#,
        )
        .bind(txid)
        .bind(outpoint.vout)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row_opt.map(|r| (r.proof.0, r.txout.0)))
    }

    /// Insert the unspent lrc20 outpoint for the given outpoint.
    /// The default value for `spent` is false.
    async fn insert_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
        receipt_proof: ReceiptProof,
        txout: TxOut,
    ) -> eyre::Result<()> {
        let txid = outpoint.txid.to_string();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO lrc20_outputs (txid, vout, proof, txout)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(txid)
        .bind(outpoint.vout)
        .bind(Json(receipt_proof))
        .bind(Json(txout))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Iterate through all unspent lrc20 outpoints
    async fn stream_unspent_lrc20_outputs<'a>(
        &'a self,
    ) -> StorageStream<'a, (OutPoint, (ReceiptProof, TxOut))> {
        #[derive(sqlx::FromRow)]
        struct UnspentLrc20OutpointRow {
            txid: String,
            vout: i64,
            proof: Json<ReceiptProof>,
            txout: Json<TxOut>,
        }

        let stream = sqlx::query_as::<_, UnspentLrc20OutpointRow>(
            r#"
            SELECT txid, vout, proof, txout
            FROM lrc20_outputs WHERE state = 0
            "#,
        )
        .fetch(&self.pool)
        .map_err(eyre::Report::from)
        .and_then(|v| async move {
            let txid = Txid::from_str(&v.txid)?;

            Ok((OutPoint::new(txid, v.vout as u32), (v.proof.0, v.txout.0)))
        });

        Box::pin(stream) as _
    }

    async fn set_lrc20_output_state(
        &self,
        outpoint: OutPoint,
        state: Lrc20OutputState,
    ) -> eyre::Result<()> {
        sqlx::query(
            r#"
            UPDATE lrc20_outputs SET state = ?
            WHERE txid = ? AND vout = ?
            "#,
        )
        .bind(state as u8)
        .bind(outpoint.txid.to_string())
        .bind(outpoint.vout)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

impl DB {
    async fn get_value_by_key(&self, key: &str) -> eyre::Result<Option<String>> {
        sqlx::query_scalar(
            r#"
            SELECT value FROM key_value
            WHERE key = ?
            "#,
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn insert_value_by_key(&self, key: &str, value: String) -> eyre::Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO key_value (key, value)
            VALUES (?, ?)
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .map_ok(|_| ())
        .map_err(Into::into)
        .await
    }
}

const LAST_PAGE_NUM_KEY: &str = "last_indexed_page";

const CONNECTED_NODE_ID_KEY: &str = "connected_node_id";

#[async_trait]
impl KeyValueStorage for DB {
    /// Get the last indexed page number
    async fn last_indexed_page_number(&self) -> eyre::Result<u64> {
        let number_str_opt = self.get_value_by_key(LAST_PAGE_NUM_KEY).await?;

        let Some(number_str) = number_str_opt else {
            return Ok(0);
        };

        let number: u64 = number_str.parse().wrap_err("Invalid page number in DB")?;

        Ok(number)
    }

    /// Put the last indexed page number
    async fn put_last_indexed_page_number(&self, page_number: u64) -> eyre::Result<()> {
        let number_str = page_number.to_string();

        self.insert_value_by_key(LAST_PAGE_NUM_KEY, number_str)
            .await
    }

    /// Get the unique identifier of the node to which the application
    /// previously synced.
    async fn connected_node_id(&self) -> eyre::Result<Option<String>> {
        self.get_value_by_key(CONNECTED_NODE_ID_KEY).await
    }

    /// Put the unique identifier of the node to which the application
    /// previously synced.
    async fn put_connected_node_id(&self, node_id: String) -> eyre::Result<()> {
        self.insert_value_by_key(CONNECTED_NODE_ID_KEY, node_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::WalletStorage;

    #[test]
    fn test_check_inmemory_implements_wallet_storage() {
        fn assert_impl<T: WalletStorage>() {}

        assert_impl::<DB>();
    }
}
