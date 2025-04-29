use std::{io::Cursor, str::FromStr};

use bdk::bitcoincore_rpc::RawTx;
use bitcoin::{
    Address, Network, PublicKey,
    consensus::{Decodable, Encodable},
};
use pyo3::pyfunction;

use lrc20_receipts::TokenPubkey;
use lrc20_types::Lrc20Transaction;

use crate::txbuilder::PyLrc20Transaction;

#[pyfunction]
pub fn encode_lrc20_tx(tx: PyLrc20Transaction) -> eyre::Result<String> {
    let mut bytes = Vec::new();
    tx.0.consensus_encode(&mut bytes)?;

    Ok(hex::encode(bytes))
}

#[pyfunction]
pub fn decode_lrc20_tx(tx_hex: String) -> eyre::Result<PyLrc20Transaction> {
    let bytes = hex::decode(tx_hex)?;
    let mut writer = Cursor::new(bytes);

    Ok(Lrc20Transaction::consensus_decode(&mut writer)?.into())
}

#[pyfunction]
pub fn lrc20_tx_json(tx: PyLrc20Transaction) -> eyre::Result<String> {
    Ok(serde_json::to_string(&tx.0)?)
}

#[pyfunction]
pub fn bitcoin_tx_hex(tx: PyLrc20Transaction) -> String {
    tx.0.bitcoin_tx.raw_hex()
}

#[pyfunction]
pub fn txid(tx: PyLrc20Transaction) -> String {
    tx.0.bitcoin_tx.txid().to_string()
}

#[pyfunction]
pub fn pubkey_to_p2tr(pubkey_str: String, network_str: String) -> eyre::Result<String> {
    let pubkey = PublicKey::from_str(&pubkey_str)?;
    let network = Network::from_str(&network_str)?;
    let address = TokenPubkey::from(pubkey).to_address(network);

    Ok(address.to_string())
}

#[pyfunction]
pub fn pubkey_to_p2wpkh(pubkey_str: String, network_str: String) -> eyre::Result<String> {
    let pubkey = PublicKey::from_str(&pubkey_str)?;
    let network = Network::from_str(&network_str)?;
    let address = Address::p2wpkh(&pubkey, network)?;

    Ok(address.to_string())
}
