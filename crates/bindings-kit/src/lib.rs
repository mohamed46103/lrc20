use key::{PyPrivateKey, PyPublicKey};
use pyo3::{Bound, PyResult, pymodule, types::PyModule, wrap_pyfunction};
use txbuilder::{
    AnnouncementTransactionBuilder, BuilderInput, IssuanceTransactionBuilder, OutPoint,
    PyLrc20Transaction, ReceiptProof, SweepTransactionBuilder, TransferTransactionBuilder,
};

pub mod key;
pub mod txbuilder;
pub mod txsigner;
pub mod util;

#[pymodule]
fn lrcdk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<IssuanceTransactionBuilder>()?;
    m.add_class::<TransferTransactionBuilder>()?;
    m.add_class::<AnnouncementTransactionBuilder>()?;
    m.add_class::<SweepTransactionBuilder>()?;
    m.add_class::<BuilderInput>()?;
    m.add_class::<ReceiptProof>()?;
    m.add_class::<PyLrc20Transaction>()?;
    m.add_class::<OutPoint>()?;
    m.add_class::<PyPrivateKey>()?;
    m.add_class::<PyPublicKey>()?;

    m.add_function(wrap_pyfunction!(util::encode_lrc20_tx, m)?)?;
    m.add_function(wrap_pyfunction!(util::decode_lrc20_tx, m)?)?;
    m.add_function(wrap_pyfunction!(util::bitcoin_tx_hex, m)?)?;
    m.add_function(wrap_pyfunction!(util::lrc20_tx_json, m)?)?;
    m.add_function(wrap_pyfunction!(util::txid, m)?)?;
    m.add_function(wrap_pyfunction!(util::pubkey_to_p2tr, m)?)?;
    m.add_function(wrap_pyfunction!(util::pubkey_to_p2wpkh, m)?)?;

    Ok(())
}
