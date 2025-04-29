//! This module provide storage implementation of the wallet which required
//! access to local file system.

use std::path::PathBuf;

use bdk::database::SqliteDatabase;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

use crate::{
    AnyBitcoinProvider, Wallet,
    bitcoin_provider::BitcoinProvider,
    database::{sqlite, wrapper::DatabaseWrapper},
};

use super::WalletConfig;

const LRC20_DATA_DIR_NAME: &str = "lrc20";
const BITCOIN_TXS_DIR_NAME: &str = "bitcoin";

/// Wallet that stores transaction and data in local file storage.
///
/// LevelDB for LRC20 transactions and SQLite for Bitcoin transactions.
pub type StorageWallet =
    Wallet<HttpClient, sqlite::DB, AnyBitcoinProvider, DatabaseWrapper<SqliteDatabase>>;

pub struct StorageWalletConfig {
    /// Configuration parameters for wallet.
    pub inner: WalletConfig,

    /// Path to directory where transactions will be stored.
    pub storage_path: PathBuf,
}

impl StorageWallet {
    pub async fn from_storage_config(config: StorageWalletConfig) -> eyre::Result<Self> {
        let signer_key = config.inner.privkey;
        let network = config.inner.network;

        let bitcoin_provider = BitcoinProvider::from_config(config.inner.clone().try_into()?)?;
        let lrc20_client = HttpClientBuilder::new().build(config.inner.lrc20_url.clone())?;

        let lrc20_txs_storage = sqlite::DB::new(sqlite::Config {
            path: config.storage_path.join(LRC20_DATA_DIR_NAME),
        })
        .await?;

        let bitcoin_txs_storage = DatabaseWrapper::new(SqliteDatabase::new(
            config.storage_path.join(BITCOIN_TXS_DIR_NAME),
        ));

        Self::new(
            config.inner,
            signer_key,
            network,
            lrc20_client,
            lrc20_txs_storage,
            bitcoin_provider,
            bitcoin_txs_storage,
        )
    }
}
