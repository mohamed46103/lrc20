use bitcoin::PrivateKey;
use bitcoin::PublicKey;
use bitcoin::key::Secp256k1;
use hex;
use pyo3::exceptions::PyRuntimeError;
use pyo3::{PyResult, pyclass, pymethods};
use std::str::FromStr;

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyPrivateKey(pub PrivateKey);

#[pymethods]
impl PyPrivateKey {
    #[new]
    pub fn new(wif: String) -> PyResult<Self> {
        PrivateKey::from_wif(&wif)
            .map(Self)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn wif(&self) -> String {
        self.0.to_wif()
    }

    pub fn public(&self) -> PyPublicKey {
        let ctx = Secp256k1::new();
        PyPublicKey(self.0.public_key(&ctx))
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyPublicKey(pub PublicKey);

#[pymethods]
impl PyPublicKey {
    #[new]
    pub fn new(hex_str: String) -> PyResult<Self> {
        PublicKey::from_str(&hex_str)
            .map(Self)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }
}
