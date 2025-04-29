use std::path::PathBuf;

use bdk::blockchain::rpc::Auth;
use bitcoin::{Network, PrivateKey, secp256k1::rand::thread_rng};
use clap::Args;
use color_eyre::eyre;
use lrcdk::{
    bitcoin_provider::{BitcoinProviderConfig, BitcoinRpcConfig},
    types::FeeRateStrategy,
};

use crate::actions::generate::utils::get_default_storage_directory;
use crate::{
    config::{Config, Lrc20NodeConfig},
    context::Context,
};

#[derive(Args, Debug)]
pub struct GenerateConfigArgs {
    /// The path to the config file to generate
    output: PathBuf,

    /// Path where the storage should be stored
    #[clap(long, short, default_value_os_t = get_default_storage_directory())]
    storage: PathBuf,

    /// Network to generate the config for
    #[clap(long, short, default_value = "regtest")]
    network: Network,
}

const DEFAULT_FEERATE_STRATEGY: FeeRateStrategy = FeeRateStrategy::Manual { fee_rate: 1.0 };

pub(crate) fn run(args: GenerateConfigArgs, context: Context) -> eyre::Result<()> {
    let secp_ctx = context.secp_ctx();

    let (priv_key, _pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    let config = Config {
        private_key: PrivateKey::new(priv_key, args.network),
        bitcoin_provider: BitcoinProviderConfig::BitcoinRpc(BitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            network: args.network,
            auth: Auth::UserPass {
                username: "admin1".to_string(),
                password: "123".to_string(),
            },
            start_time: 0,
        }),
        lrc20_rpc: Lrc20NodeConfig {
            url: "http://127.0.0.1:18333".to_string(),
        },
        fee_rate_strategy: DEFAULT_FEERATE_STRATEGY,
        storage: args.storage,
    };

    config.save_to_file(args.output)?;

    Ok(())
}
