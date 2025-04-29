use bitcoin::{BlockHash, Transaction, Txid};
use lrc20_types::{Lrc20Transaction, Lrc20TxType};
use serde::Deserialize;

#[cfg(any(feature = "client", feature = "server"))]
mod rpc;
#[cfg(any(feature = "client", feature = "server"))]
pub use self::rpc::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
/// Describes LRC20 transaction status.
pub enum Lrc20TransactionStatus {
    /// Transaction is not found.
    ///
    /// Provided proof was rejected, or no proofs were provided yet.
    None,
    /// Transaction is found, it's raw data is provided, but it's in the queue to be checked.
    Initialized,
    /// Transaction is found, it's raw data is provided, it's partially checked, but hasn't
    /// appeared in the blockchain yet.
    WaitingMined,
    /// Transaction is found, it's raw data is provided, it's partially checked, but is waiting for
    /// enough confirmations.
    Mined,
    /// Transaction is found, it's raw data is provided, it's fully checked, but is waiting to get
    /// attached.
    Attaching,
    /// Transaction is found, it's raw data is provided, it's fully checked, and the node has
    /// all parent transactions to attach it.
    Attached,
    /// TODO: This status is used for `get_raw_lrc20_transaction` only and will soon be removed.
    Pending,
}

#[allow(deprecated)]
impl From<lrc20_storage::entities::sea_orm_active_enums::MempoolStatus> for Lrc20TransactionStatus {
    fn from(value: lrc20_storage::entities::sea_orm_active_enums::MempoolStatus) -> Self {
        match value {
            lrc20_storage::entities::sea_orm_active_enums::MempoolStatus::Initialized => {
                Self::Initialized
            }
            lrc20_storage::entities::sea_orm_active_enums::MempoolStatus::WaitingMined => {
                Self::WaitingMined
            }
            lrc20_storage::entities::sea_orm_active_enums::MempoolStatus::Pending => Self::Pending,
            lrc20_storage::entities::sea_orm_active_enums::MempoolStatus::Mined => Self::Mined,
            lrc20_storage::entities::sea_orm_active_enums::MempoolStatus::Attaching => {
                Self::Attaching
            }
        }
    }
}

/// Json encoded response for [`getrawlrc20transaction`](Lrc20TransactionsRpcServer::get_raw_lrc20_transaction) RPC
/// method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct GetRawLrc20TransactionResponseJson {
    pub status: Lrc20TransactionStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Lrc20TransactionResponse>,
}

impl GetRawLrc20TransactionResponseJson {
    pub fn new(status: Lrc20TransactionStatus, data: Option<Lrc20TransactionResponse>) -> Self {
        Self { status, data }
    }
}

/// Hex encoded response for [`getlrc20transaction`](Lrc20TransactionsRpcServer::get_lrc20_transaction) RPC
/// method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct GetRawLrc20TransactionResponseHex {
    pub status: Lrc20TransactionStatus,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(
        serialize_with = "lrc20_tx_to_hex",
        deserialize_with = "hex_to_lrc20_tx"
    )]
    pub data: Option<Lrc20TransactionResponse>,
}

impl GetRawLrc20TransactionResponseHex {
    pub fn new(status: Lrc20TransactionStatus, data: Option<Lrc20TransactionResponse>) -> Self {
        Self { status, data }
    }
}

pub fn lrc20_tx_to_hex<S>(
    lrc20_tx: &Option<Lrc20TransactionResponse>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match lrc20_tx {
        Some(tx) => serializer.serialize_str(&Lrc20Transaction::from(tx.clone()).hex()),
        None => serializer.serialize_none(),
    }
}

pub fn hex_to_lrc20_tx<'de, D>(
    deserializer: D,
) -> Result<Option<Lrc20TransactionResponse>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt_hex = Option::<String>::deserialize(deserializer)?;
    match opt_hex {
        Some(hex) => {
            let tx = Lrc20Transaction::from_hex(hex).map_err(serde::de::Error::custom)?;
            Ok(Some(Lrc20TransactionResponse::from(tx)))
        }
        None => Ok(None),
    }
}

/// Response for [`emulatelrc20transaction`](Lrc20TransactionsRpcServer::emulate_lrc20_transaction) RPC
/// method that is defined for returning reason of transaction rejection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "data")]
pub enum EmulateLrc20TransactionResponse {
    /// Transaction will be rejected by node for given reason.
    Invalid { reason: String },

    /// Transaction could be accepted by node.
    Valid,
}

impl EmulateLrc20TransactionResponse {
    pub fn invalid(reason: String) -> Self {
        Self::Invalid { reason }
    }
}

/// A wrapper around [`bitcoin::blockdata::transaction`] that contains `Txid`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TransactionResponse {
    pub txid: Txid,

    #[serde(flatten)]
    pub bitcoin_tx: Transaction,
}

impl From<Transaction> for TransactionResponse {
    fn from(bitcoin_tx: Transaction) -> Self {
        Self {
            txid: bitcoin_tx.txid(),
            bitcoin_tx,
        }
    }
}

impl From<TransactionResponse> for Transaction {
    fn from(tx: TransactionResponse) -> Self {
        tx.bitcoin_tx
    }
}

impl From<Lrc20TransactionResponse> for Lrc20Transaction {
    fn from(response: Lrc20TransactionResponse) -> Self {
        Self::new(response.bitcoin_tx.into(), response.tx_type)
    }
}

impl From<Lrc20Transaction> for Lrc20TransactionResponse {
    fn from(tx: Lrc20Transaction) -> Self {
        Self {
            bitcoin_tx: tx.bitcoin_tx.into(),
            tx_type: tx.tx_type,
        }
    }
}

/// Response for [`listlrc20transactions`] RPC method that is defined for returning the list of
/// attached LRC20 transactions.
///
/// [`listlrc20transactions`]: Lrc20TransactionsRpcServer::list_lrc20_transactions
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Lrc20TransactionResponse {
    pub bitcoin_tx: TransactionResponse,
    pub tx_type: Lrc20TxType,
}

/// Request for [`providelrc20proof`] and [`providelistlrc20proofs`] RPC methods that are defined for
/// providing LRC20 proofs without broadcasting the Bitcoin tx.
///
/// [`providelrc20proof`]: Lrc20TransactionsRpcServer::provide_lrc20_proof
/// [`providelistlrc20proofs`]: Lrc20TransactionsRpcServer::provide_list_lrc20_proofs
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProvideLrc20ProofRequest {
    pub txid: Txid,
    #[serde(serialize_with = "tx_type_to_hex", deserialize_with = "hex_to_tx_type")]
    pub tx_type: Lrc20TxType,
    pub blockhash: Option<BlockHash>,
}

pub fn tx_type_to_hex<S>(tx_type: &Lrc20TxType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&tx_type.hex())
}

pub fn hex_to_tx_type<'de, D>(deserializer: D) -> Result<Lrc20TxType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    Lrc20TxType::from_hex(hex).map_err(serde::de::Error::custom)
}

impl ProvideLrc20ProofRequest {
    pub fn new(txid: Txid, tx_type: Lrc20TxType, blockhash: Option<BlockHash>) -> Self {
        Self {
            txid,
            tx_type,
            blockhash,
        }
    }
}
