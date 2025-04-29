use alloc::vec::Vec;
use bitcoin::Txid;
use bitcoin_client::json::GetBlockTxResult;
use core::fmt::Debug;
use event_bus::Event;
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::{
    Lrc20Transaction,
    spark::{TokenTransaction, TokensFreezeData, signature::SparkSignatureData},
};

use self::p2p::Inventory;

pub mod p2p;

/// Messages to Controller service.
#[derive(Clone, Debug, Event)]
pub enum ControllerMessage {
    /// Notification about invalid transactions.
    InvalidTxs(Vec<Txid>),
    /// Ask for data about transactions in P2P network.
    GetData {
        /// Ids of transactions to get.
        inv: Vec<Inventory>,
        /// Peer id of the sender.
        receiver: SocketAddr,
    },
    /// Tranactions that passed the isolated check and are ready to be sent for confirmation.
    PartiallyCheckedTxs(Vec<Txid>),
    /// Tranactions that passed the full check and are ready to be sent to tx attacher.
    FullyCheckedTxs(Vec<Lrc20Transaction>),
    /// Valid Spark transactions.
    CheckedSparkTxs(Vec<TokenTransaction>),
    /// Valid Spark freeze data.
    CheckedSparkFreezeData(Vec<TokensFreezeData>),
    /// Share transactions with one confirmation with the P2P peers.
    MinedTxs(Vec<Txid>),
    /// Send confirmed transactions to the tx checker for a full check.
    ConfirmedTxs(Vec<Txid>),
    /// Send signed transactions for on-chain confirmation.
    InitializeTxs(Vec<Lrc20Transaction>),
    /// Send Spark transactions for a check.
    NewSparkTxs(Vec<TokenTransaction>, Option<mpsc::Sender<bool>>),
    /// Send Spark transactions for a check.
    NewSparkSignaturesRequest(Vec<SparkSignatureData>, Option<mpsc::Sender<bool>>),
    /// Send Spark freeze tokens requests for a check.
    NewFreezeTokensRequest(Vec<TokensFreezeData>),
    /// Handle a reorg.
    Reorganization {
        txs: Vec<Txid>,
        new_indexing_height: usize,
    },
    /// New inventory to share with peers.
    AttachedTxs(Vec<Txid>),
    /// New inventory to share with peers.
    AttachedSparkTxs(Vec<TokenTransaction>),
    /// Data that is received from p2p.
    P2P(ControllerP2PMessage),
    /// The indexer has finished the initial sync so the controller can inform the P2P
    /// that it can start handling events.
    InitialIndexingFinished,
}

/// Message from P2P to Controller.
#[derive(Clone, Debug, Event)]
pub enum ControllerP2PMessage {
    /// Ask current state of the node's inventory.
    Inv {
        inv: Vec<Inventory>,
        /// Address of the sender.
        sender: SocketAddr,
    },
    /// Provide transactions data to the node.
    GetData {
        inv: Vec<Inventory>,
        /// Address of the sender.
        sender: SocketAddr,
    },
    /// Response of [`ControllerP2PMessage::GetData`].
    Lrc20Tx {
        txs: Vec<Lrc20Transaction>,
        /// Address of the sender.
        sender: SocketAddr,
    },
    SparkTxs {
        txs: Vec<TokenTransaction>,
        /// Address of the sender.
        sender: SocketAddr,
    },
    SparkSignatureData {
        data: Vec<SparkSignatureData>,
        /// Address of the sender.
        sender: SocketAddr,
    },
}

/// Message to TxChecker service.
#[derive(Clone, Debug, Event)]
pub enum TxCheckerMessage {
    /// New transactions to pass the full check. The transactions come along with the peer id of
    /// the sender:
    /// * Some if transactions received from p2p network
    /// * None if transactions received via json rpc
    FullCheck(Vec<(Lrc20Transaction, Option<SocketAddr>)>),
    /// New transactions to pass the isolated check.
    IsolatedCheck(Vec<Lrc20Transaction>),
    /// New Spark transactions to pass the check.
    SparkCheck(
        (
            Vec<TokenTransaction>,
            Option<SocketAddr>,
            Option<mpsc::Sender<bool>>,
        ),
    ),
    /// New Spark revocation keys to pass the check.
    SparkSignatureCheck(Vec<SparkSignatureData>, Option<mpsc::Sender<bool>>),
    /// New Spark tokens freeze request to pass the check.
    TokensFreezeCheck(Vec<TokensFreezeData>),
}

/// Message to GraphBuilder service.
#[derive(Clone, Debug, Event)]
pub enum GraphBuilderMessage {
    /// Transactions to attach that already have been checked.
    CheckedTxs(Vec<Lrc20Transaction>),
}

/// Message to SparkGraphBuilder
#[derive(Clone, Debug, Event)]
pub enum SparkGraphBuilderMessage {
    /// Transactions to attach that already have been checked.
    CheckedTxs(Vec<TokenTransaction>),
}

/// Message to ConfirmationIndexer.
#[derive(Clone, Debug, Event)]
pub enum TxConfirmMessage {
    /// Transactions that should be confirmed before sending to the tx checker.
    Txs(Vec<Txid>),
    /// Transactions that are confirmed.
    Block(Box<GetBlockTxResult>),
}

/// Message to Indexer service.
#[derive(Clone, Debug, Event)]
pub enum IndexerMessage {
    /// New height to index blocks from. Sent from the controller in case of reorg.
    Reorganization(usize),
}
