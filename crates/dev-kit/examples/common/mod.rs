use bdk::{
    blockchain::{ConfigurableBlockchain, RpcBlockchain, RpcConfig, rpc::Auth},
    descriptor,
    wallet::wallet_name_from_descriptor,
};
use bitcoin::{Address, Network, PrivateKey, Txid, secp256k1::Secp256k1};
use bitcoin_client::BitcoinRpcApi;
use jsonrpsee::http_client::HttpClient;
use lrcdk::{
    bitcoin_provider::{BitcoinProviderConfig, BitcoinRpcConfig},
    wallet::{MemoryWallet, WalletConfig},
};

use lrc20_rpc_api::transactions::{
    GetRawLrc20TransactionResponseHex, Lrc20TransactionStatus, Lrc20TransactionsRpcClient,
};
use once_cell::sync::Lazy;

/*
* Participants private keys used across examples.
*/

pub static USD_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9"
        .parse()
        .expect("Should be valid key")
});

pub static EUR_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cUK2ZdLQWWpKeFcrrD7BBjiUsEns9M3MFBTkmLTXyzs66TQN72eX"
        .parse()
        .expect("Should be valid key")
});

pub static ALICE: Lazy<PrivateKey> = Lazy::new(|| {
    "cQb7JarJTBoeu6eLvyDnHYNr6Hz4AuAnELutxcY478ySZy2i29FA"
        .parse()
        .expect("Should be valid key")
});

pub static BOB: Lazy<PrivateKey> = Lazy::new(|| {
    "cUrMc62nnFeQuzXb26KPizCJQPp7449fsPsqn5NCHTwahSvqqRkV"
        .parse()
        .expect("Should be valid key")
});

/// Funds address with Bitcoins by generating blocks and giving
/// it the rewards of the coinbase transaction.
pub async fn fund_address(addr: &Address) -> eyre::Result<()> {
    let client = local_bitcoin_client().await?;

    client.generate_to_address(101, addr).await?;

    Ok(())
}

pub async fn mine_blocks(num: u64) -> eyre::Result<()> {
    let client = local_bitcoin_client().await?;

    client
        .generate_to_address(
            num,
            &Address::p2wpkh(&USD_ISSUER.public_key(&Secp256k1::new()), Network::Regtest)?,
        )
        .await?;

    Ok(())
}

async fn local_bitcoin_client() -> Result<bitcoin_client::BitcoinRpcClient, eyre::Error> {
    Ok(bitcoin_client::BitcoinRpcClient::new(
        bitcoin_client::BitcoinRpcAuth::UserPass {
            username: LOCAL_BITCOIN_RPC_USERNAME.to_string(),
            password: LOCAL_BITCOIN_RPC_PASSWORD.to_string(),
        },
        LOCAL_BITCOIN_RPC_URL.to_string(),
        None,
    )
    .await?)
}

/// Wait until the transaction is attached to the block or rejected.
pub async fn wait_until_reject_or_attach(
    txid: Txid,
    lrc20_client: &HttpClient,
) -> eyre::Result<GetRawLrc20TransactionResponseHex> {
    let mut tx = lrc20_client.get_lrc20_transaction(txid).await?;

    while !matches!(tx.status, Lrc20TransactionStatus::Attached) {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        tx = lrc20_client.get_lrc20_transaction(txid).await?;
    }

    Ok(tx)
}

pub fn wallet_from_private_key(private_key: PrivateKey) -> eyre::Result<MemoryWallet> {
    // Set up the wallet config.
    let wallet_config = WalletConfig {
        privkey: private_key,
        network: bitcoin::Network::Regtest,
        bitcoin_provider: LOCAL_BITCOIN_PROVIDER.clone(),
        lrc20_url: LOCAL_LRC20_URL.to_string(),
    };

    // Build a wallet from the config.
    MemoryWallet::from_config(wallet_config)
}

/**
* Configurations to connect to local Bitcoin, LRC20 and Esplora nodes using
* our docker-compose setup.
*/

pub const LOCAL_BITCOIN_RPC_URL: &str = "http://127.0.0.1:18443";
pub const LOCAL_BITCOIN_RPC_PASSWORD: &str = "123";
pub const LOCAL_BITCOIN_RPC_USERNAME: &str = "admin1";

pub static LOCAL_BITCOIN_PROVIDER: Lazy<BitcoinProviderConfig> = Lazy::new(|| {
    BitcoinProviderConfig::BitcoinRpc(BitcoinRpcConfig {
        url: LOCAL_BITCOIN_RPC_URL.to_string(),
        auth: Auth::UserPass {
            username: LOCAL_BITCOIN_RPC_USERNAME.to_string(),
            password: LOCAL_BITCOIN_RPC_PASSWORD.to_string(),
        },
        network: bitcoin::Network::Regtest,
        start_time: 0,
    })
});

pub const LOCAL_LRC20_URL: &str = "http://127.0.0.1:18333";

pub const LOCAL_ESPLORA_URL: &str = "http://127.0.0.1:30000";

pub static RPC_BLOCKCHAIN: Lazy<RpcBlockchain> = Lazy::new(|| {
    let secp_ctx = Secp256k1::new();

    let wallet_name = wallet_name_from_descriptor(
        descriptor!(wpkh(*USD_ISSUER)).unwrap(),
        None,
        Network::Regtest,
        &secp_ctx,
    )
    .unwrap();

    let config = RpcConfig {
        url: LOCAL_BITCOIN_RPC_URL.to_string(),
        auth: Auth::UserPass {
            username: LOCAL_BITCOIN_RPC_USERNAME.to_string(),
            password: LOCAL_BITCOIN_RPC_PASSWORD.to_string(),
        },
        network: Network::Regtest,
        wallet_name,
        sync_params: None,
    };

    RpcBlockchain::from_config(&config).unwrap()
});
