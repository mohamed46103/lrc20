//! This module provides definition for wallet which works fully in memory.

use bdk::database::MemoryDatabase;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

use crate::{
    AnyBitcoinProvider, Wallet,
    bitcoin_provider::BitcoinProvider,
    database::{self, inmemory::SafeInMemoryDB, wrapper::DatabaseWrapper},
};

use super::WalletConfig;

pub type MemoryWallet =
    Wallet<HttpClient, SafeInMemoryDB, AnyBitcoinProvider, DatabaseWrapper<MemoryDatabase>>;

impl MemoryWallet {
    pub fn from_config(config: WalletConfig) -> eyre::Result<Self> {
        let signer_key = config.privkey;
        let network = config.network;

        let bitcoin_provider = BitcoinProvider::from_config(config.clone().try_into()?)?;
        let lrc20_client = HttpClientBuilder::new().build(config.lrc20_url.clone())?;

        let lrc20_txs_storage = database::in_memory();
        let bitcoin_txs_storage = DatabaseWrapper::new(MemoryDatabase::default());

        Self::new(
            config,
            signer_key,
            network,
            lrc20_client,
            lrc20_txs_storage,
            bitcoin_provider,
            bitcoin_txs_storage,
        )
    }
}
