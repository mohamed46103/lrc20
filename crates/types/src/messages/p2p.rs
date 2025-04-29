#[cfg(feature = "consensus")]
use std::io::{self, Read};

#[cfg(feature = "consensus")]
use crate::consensus::{InventoryWrapper, Lrc20TxsWrapper, SparkSigsWrapper, SparkTxsWrapper};

use crate::{
    Lrc20Transaction,
    spark::{TokenTransaction, TokensFreezeData, signature::SparkSignatureData},
};
use alloc::vec::Vec;

#[cfg(feature = "consensus")]
use alloc::vec;

#[cfg(feature = "consensus")]
use bitcoin::consensus::{
    Decodable, Encodable,
    encode::{self, CheckedData},
};

use bitcoin::{
    Txid,
    hashes::sha256::Hash,
    p2p::{Address, Magic, message::CommandString, message_network::VersionMessage},
};

#[cfg(feature = "consensus")]
const MAX_MSG_SIZE: u64 = 5_000_000;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Inventory {
    /// Lrc20 tx ids
    Ltx(Txid),
    /// Spark transaction hash
    SparkTx(Hash),
    /// Spark signature data id (leaf hash it belongs to)
    SparkSignatures(Hash),
    /// Spark freeze data
    SparkFreeze(TokensFreezeData),
}

impl From<&Txid> for Inventory {
    fn from(txid: &Txid) -> Self {
        Self::Ltx(*txid)
    }
}

/// Raw message which is sent between peers
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawNetworkMessage {
    pub magic: Magic,
    pub payload: NetworkMessage,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NetworkMessage {
    /// INV method. Contains a list of recent inventory data.
    Inv(Vec<Inventory>),

    /// ADDR method. Contains a list of peers.
    /// - u32: the time the peer was last active, in seconds since unix epoch.
    /// - Address: The address of the peer.
    Addr(Vec<(u32, Address)>),

    /// GETADDR method. Used to request a list of known active peers from another peer. Receiver
    /// can respond with ADDR to share their peers.
    GetAddr,

    /// GET DATA method. Contains list of transaction ids to request
    GetData(Vec<Inventory>),

    /// LRC20 TX method. Contains list of transactions
    Lrc20Tx(Vec<Lrc20Transaction>),

    /// Spark TX method. Contains list of transactions
    SparkTx(Vec<TokenTransaction>),

    /// Spark TX method. Contains list of transactions
    SparkSig(Vec<SparkSignatureData>),

    /// PING method. Contains random nonce
    Ping(u64),

    /// PONG method. Contains same nonce that was received by PING method
    Pong(u64),

    /// VERACK method
    Verack,

    /// VERSION method
    Version(VersionMessage),

    /// WTXIDRELAY method (defines whether the node supports BIP 339)
    WtxidRelay,

    /// LTXIDRELAY method (defines whether the node supports LRC20 protocol )
    LtxidRelay,

    /// LTXIDACK method (acknowledges the support of LRC20 protocol )
    Ltxidack,

    /// Any other message.
    Unknown {
        /// The command of this message.
        command: CommandString,
        /// The payload of this message.
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    pub fn cmd(&self) -> &'static str {
        match *self {
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::Lrc20Tx(_) => "lrc20tx",
            NetworkMessage::SparkTx(_) => "sparktx",
            NetworkMessage::SparkSig(_) => "sparksig",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Version(_) => "version",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::LtxidRelay => "ltxidrelay",
            NetworkMessage::Ltxidack => "ltxidack",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Unknown { .. } => "unknown",
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands")
    }
}

impl RawNetworkMessage {
    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

#[cfg(feature = "consensus")]
impl Encodable for RawNetworkMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(w)?;
        len += self.command().consensus_encode(w)?;
        len += CheckedData::new(match self.payload {
            NetworkMessage::Inv(ref dat) => serialize_consensus(&InventoryWrapper(dat.to_vec())),
            NetworkMessage::Addr(ref dat) => serialize_consensus(dat),
            NetworkMessage::GetData(ref dat) => {
                serialize_consensus(&InventoryWrapper(dat.to_vec()))
            }
            NetworkMessage::Lrc20Tx(ref dat) => serialize_consensus(&Lrc20TxsWrapper(dat.to_vec())),
            NetworkMessage::SparkTx(ref dat) => serialize_consensus(&SparkTxsWrapper(dat.to_vec())),
            NetworkMessage::SparkSig(ref dat) => {
                serialize_consensus(&SparkSigsWrapper(dat.to_vec()))
            }
            NetworkMessage::Ping(ref dat) => serialize_consensus(dat),
            NetworkMessage::Pong(ref dat) => serialize_consensus(dat),
            NetworkMessage::Verack
            | NetworkMessage::WtxidRelay
            | NetworkMessage::LtxidRelay
            | NetworkMessage::Ltxidack
            | NetworkMessage::GetAddr => vec![],
            NetworkMessage::Version(ref dat) => serialize_consensus(dat),
            NetworkMessage::Unknown {
                payload: ref dat, ..
            } => serialize_consensus(dat),
        })
        .consensus_encode(w)?;
        Ok(len)
    }
}

#[cfg(feature = "consensus")]
pub fn serialize_consensus<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data
        .consensus_encode(&mut encoder)
        .expect("in-memory writers don't error");
    debug_assert_eq!(len, encoder.len());
    encoder
}

#[cfg(feature = "consensus")]
impl Decodable for RawNetworkMessage {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode(r)?;
        let cmd = CommandString::consensus_decode(r)?;
        let raw_payload = CheckedData::consensus_decode(r)?.into_data();

        let mut mem_d = io::Cursor::new(raw_payload.clone());

        let payload = match &cmd.to_string()[..] {
            "inv" => NetworkMessage::Inv(InventoryWrapper::consensus_decode(&mut mem_d)?.0),
            "getdata" => NetworkMessage::GetData(InventoryWrapper::consensus_decode(&mut mem_d)?.0),
            "lrc20tx" => {
                let txs = Lrc20TxsWrapper::consensus_decode(&mut raw_payload.as_slice())?;
                NetworkMessage::Lrc20Tx(txs.0)
            }
            "sparktx" => {
                let txs = SparkTxsWrapper::consensus_decode(&mut raw_payload.as_slice())?;
                NetworkMessage::SparkTx(txs.0)
            }
            "sparksig" => {
                let sigs = SparkSigsWrapper::consensus_decode(&mut raw_payload.as_slice())?;
                NetworkMessage::SparkSig(sigs.0)
            }
            "ping" => NetworkMessage::Ping(Decodable::consensus_decode(&mut mem_d)?),
            "pong" => NetworkMessage::Pong(Decodable::consensus_decode(&mut mem_d)?),
            "addr" => NetworkMessage::Addr(Decodable::consensus_decode(&mut mem_d)?),
            "version" => NetworkMessage::Version(Decodable::consensus_decode(&mut mem_d)?),
            "verack" => NetworkMessage::Verack,
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "ltxidrelay" => NetworkMessage::LtxidRelay,
            "ltxidack" => NetworkMessage::Ltxidack,
            "getaddr" => NetworkMessage::GetAddr,
            _ => NetworkMessage::Unknown {
                command: cmd,
                payload: mem_d.into_inner(),
            },
        };
        Ok(RawNetworkMessage { magic, payload })
    }

    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE).by_ref())
    }
}
