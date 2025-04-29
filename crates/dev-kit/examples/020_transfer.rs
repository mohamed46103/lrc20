//! This example shows the ability to spend outputs issued to user.
//!
//! Here USD issuer issues tokens to Alice and then Alice forms a
//! transactions which spend it to Bob without broadcasting.

use bitcoin::{OutPoint, PrivateKey, secp256k1::Secp256k1};
use jsonrpsee::http_client::HttpClientBuilder;

use lrc20_receipts::{Receipt, TokenPubkey};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::{
    types::FeeRateStrategy,
    wallet::{MemoryWallet, SyncOptions, WalletConfig},
};

pub mod common;
use common::{LOCAL_BITCOIN_PROVIDER, LOCAL_LRC20_URL};

use crate::common::{
    ALICE, BOB, RPC_BLOCKCHAIN, USD_ISSUER, fund_address, mine_blocks, wait_until_reject_or_attach,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let secp_ctx = Secp256k1::new();

    // For this we'll use client to LRC20d node RPC to broadcast the transction.
    let lrc20_client = HttpClientBuilder::new().build(LOCAL_LRC20_URL)?;

    // Initialize participants keys:
    let alice_private_key = *ALICE;
    let issuer_private_key = *USD_ISSUER;

    // Create their wallest
    let alice_wallet = wallet_from_private_key(alice_private_key)?;
    let issuer_wallet = wallet_from_private_key(issuer_private_key)?;

    issuer_wallet.sync(SyncOptions::bitcoin_only()).await?;

    // Make sure that issuer has enough Bitcoins for issue transaction:
    if issuer_wallet.bitcoin_balances()?.get_spendable() < 10_000 {
        fund_address(&issuer_wallet.address()?).await?;
        issuer_wallet.sync(SyncOptions::bitcoin_only()).await?;
    }

    let issuance = {
        let mut txbuilder = issuer_wallet.build_issuance(None)?;

        // Issue 100_000 USD to Alice with satoshis so that she can pay for next transaction.
        txbuilder
            .add_recipient(
                &alice_private_key.public_key(&secp_ctx).inner,
                100_000,
                5000,
            )
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    // broadcast issuance through LRC20d node
    lrc20_client.send_lrc20_tx(issuance.hex(), None).await?;
    // Mine blocks, so the issuance is mined too
    mine_blocks(6).await?;
    // Let's wait until the transactions is rejected or attached on the LRC20d node.
    wait_until_reject_or_attach(issuance.bitcoin_tx.txid(), &lrc20_client).await?;

    // Alice must have this transaction after sync:
    alice_wallet.sync(SyncOptions::default()).await?;

    assert!(
        alice_wallet
            .lrc20_utxos()
            .await?
            // Here we know that the outpoint is the second one in the issuance transaction,
            // As usually the first one is announcement. If this doesn't work, change the vout:
            .contains_key(&OutPoint::new(issuance.bitcoin_tx.txid(), 1)),
        "Alice must have issuance UTXO after sync",
    );

    // Token type of the issuance above:
    let issuer_token_pubkey = TokenPubkey::from(issuer_private_key.public_key(&secp_ctx).inner);

    // Recipient
    let bob_pubkey = BOB.public_key(&secp_ctx).inner;

    // For simple transfers for one user you can use `create_transfer`
    let _transfer = alice_wallet
        .create_transfer(Receipt::new(50_000, issuer_token_pubkey), bob_pubkey, None)
        .await?;

    // For more complex transfers you can use `build_transfer` and specify all parameters by yourself:
    let transfer = {
        let mut txbuilder = alice_wallet.build_transfer()?;

        // Add a recipient and specify valid `TokenPubkey`, receiver's `PublicKey`, LRC20 token amount and Satoshis amount.
        txbuilder
            .add_recipient(
                // Send the token which is the same type Issuer gave Alice
                issuer_token_pubkey,
                // Send to Bob's public key
                &bob_pubkey,
                // Half of the amount
                50_000,
                // With minimal sats amount
                1000,
            )
            // For regtest, only manual fee rate strategy is available, so we set it 2 sats per byte.
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    println!("Transfer txid: {}", transfer.bitcoin_tx.txid());
    println!("tx in hex: {}", transfer.hex());
    println!(
        "Serialized tx: {}",
        serde_json::to_string_pretty(&transfer)?
    );

    Ok(())
}

fn wallet_from_private_key(private_key: PrivateKey) -> eyre::Result<MemoryWallet> {
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
