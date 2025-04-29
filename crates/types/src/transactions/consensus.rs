use core::fmt;

use crate::{Lrc20Transaction, Lrc20TxType};

use alloc::{string::String, vec::Vec};

use bitcoin::consensus::{Decodable, Encodable};
use core2::io::Cursor;
use hex::FromHexError;

impl Lrc20Transaction {
    pub fn hex(&self) -> String {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).expect("Should encode");

        hex::encode(bytes)
    }

    pub fn from_hex(hex: String) -> Result<Lrc20Transaction, Lrc20TransactionParseError> {
        let bytes = hex::decode(hex)?;
        let mut reader = Cursor::new(bytes);

        Lrc20Transaction::consensus_decode(&mut reader)
            .map_err(|_err| Lrc20TransactionParseError::InvalidTx)
    }
}

impl Lrc20TxType {
    pub fn hex(&self) -> String {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).expect("Should encode");

        hex::encode(bytes)
    }

    pub fn from_hex(hex: String) -> Result<Lrc20TxType, Lrc20TransactionParseError> {
        let bytes = hex::decode(hex)?;
        let mut reader = Cursor::new(bytes);

        Lrc20TxType::consensus_decode(&mut reader)
            .map_err(|_err| Lrc20TransactionParseError::InvalidProofs)
    }
}

/// Error that can occur when converting hex data in a `Lrc20Transaction` and vice versa.
#[derive(Debug)]
pub enum Lrc20TransactionParseError {
    /// Wrong raw transaction hex data.
    Hex(FromHexError),
    /// Hex data contains a malformed [Lrc20Transaction].
    InvalidTx,
    /// Hex data contains a malformed [Lrc20TxType].
    InvalidProofs,
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for Lrc20TransactionParseError {}

impl fmt::Display for Lrc20TransactionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lrc20TransactionParseError::Hex(err) => write!(f, "Invalid hex data: {}", err),
            Lrc20TransactionParseError::InvalidTx => write!(f, "The transaction is malformed"),
            Lrc20TransactionParseError::InvalidProofs => {
                write!(f, "Transaction proofs are malformed")
            }
        }
    }
}

impl From<FromHexError> for Lrc20TransactionParseError {
    fn from(e: FromHexError) -> Self {
        Self::Hex(e)
    }
}
