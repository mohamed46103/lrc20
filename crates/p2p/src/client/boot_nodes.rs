use std::str::FromStr;

use lrc20_types::network::Network;

use super::{P2PConfig, PeerAddr};

const TESTNET: &[&str] = &[];
const MAINNET: &[&str] = &[];
const MUTINY: &[&str] = &[];

/// Update the list of peers with the hard coded boot nodes for the given [Network].
pub(crate) fn insert_boot_nodes(config: &mut P2PConfig) {
    match config.network {
        Network::Bitcoin => {
            tracing::debug!("Adding {} mainnet boot nodes", MAINNET.len());
            insert(config, MAINNET);
        }
        Network::Testnet => {
            tracing::debug!("Adding {} testnet boot nodes", TESTNET.len());
            insert(config, TESTNET)
        }
        Network::Mutiny => {
            tracing::debug!("Adding {} Mutiny boot nodes", MUTINY.len());
            insert(config, MUTINY)
        }
        _ => {
            tracing::debug!("No boot nodes provided for the given network");
        }
    }
}

fn insert(config: &mut P2PConfig, boot_nodes: &[&str]) {
    boot_nodes.iter().for_each(|boot_node_url| {
        let boot_node_addr = PeerAddr::from_str(boot_node_url).expect("Address should be valid");
        config.connect.push(boot_node_addr)
    });
}
