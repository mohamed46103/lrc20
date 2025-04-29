use bitcoin::{
    BlockHash, TxMerkleNode, Txid,
    hashes::Hash,
    key::rand::{RngCore, thread_rng},
};
use bitcoin_client::{
    BitcoinRpcApi, MockRpcApi,
    json::{BlockData, GetBlockResult, GetBlockTxResult},
};

use jsonrpc::error::RpcError;
use std::str::FromStr;

use event_bus::EventBus;

use lrc20_types::ControllerMessage;
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, SystemTime},
};

use crate::BlockInfo;
use crate::TxConfirmator;

// Tests params
const BLOCKCHAIN_SIZE: usize = 500;
const REORG_SIZE: usize = 450;

fn make_dummy_blockdata(hash: BlockHash, prev_hash: BlockHash, height: usize) -> BlockData {
    BlockData {
        hash,
        previousblockhash: Some(prev_hash),
        nextblockhash: None,
        confirmations: u32::default(),
        size: usize::default(),
        strippedsize: None,
        weight: usize::default(),
        height,
        version: i32::default(),
        version_hex: None,
        merkleroot: TxMerkleNode::all_zeros(),
        time: usize::default(),
        mediantime: None,
        nonce: u32::default(),
        bits: String::new(),
        difficulty: f64::default(),
        chainwork: vec![],
        n_tx: usize::default(),
    }
}

// Structure which similar to blockchain, except of proof of work
fn immitate_blockchain(chain_size: usize) -> (MockRpcApi, Vec<BlockInfo>) {
    let mut block_hashes = Vec::new();
    let mut mock = MockRpcApi::new();

    block_hashes.push(
        BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("Genesis hash must be correct."),
    ); // First block in the bitocoin blockchain is genesis

    for _ in 0..(chain_size - 1) {
        let new_block = BlockHash::hash(&thread_rng().next_u64().to_be_bytes());
        block_hashes.push(new_block);
    }

    let blocks = block_hashes
        .iter()
        .map(|x| BlockInfo {
            hash: *x,
            txs: vec![],
        })
        .collect();

    mock.expect_get_block_info().returning(move |hash| {
        let Some(hash_pos) = block_hashes.iter().position(|x| x == hash) else {
            return Err(bitcoin_client::Error::JsonRpc(
                bitcoin_client::JsonRpcError::Rpc(RpcError {
                    code: -5,
                    message: "Block not found".to_owned(),
                    data: None,
                }),
            ));
        };
        let prev_hash = hash_pos
            .checked_sub(1)
            .map_or(BlockHash::all_zeros(), |prev_pos| block_hashes[prev_pos]);
        Ok(GetBlockResult {
            block_data: make_dummy_blockdata(*hash, prev_hash, hash_pos),
            tx: vec![],
        })
    });

    (mock, blocks)
}

// Init tx confirmator for further tests
fn init_tx_confirmator(
    mock_api: MockRpcApi,
    latest_blocks: VecDeque<BlockInfo>,
    tx_queue: HashMap<Txid, SystemTime>,
) -> TxConfirmator<MockRpcApi> {
    let mut event_bus = EventBus::default();
    event_bus.register::<ControllerMessage>(None);
    TxConfirmator {
        event_bus,
        bitcoin_client: mock_api.into(),
        max_confirmation_time: Duration::from_secs(9999),
        clean_up_interval: Duration::from_secs(9999),
        confirmations_number: 6,
        queue: tx_queue,
        latest_blocks,
    }
}

// Test if generated blockain works as intended
#[tokio::test]
async fn test_dummy_blockchain() {
    let (rpc_mock, dummy_blockchain) = immitate_blockchain(1000);
    let mut prev_hash = BlockHash::all_zeros();
    for block in dummy_blockchain {
        let hash = &block.hash;
        assert_eq!(
            rpc_mock.get_block_info(hash).await.unwrap().block_data.hash,
            *hash
        );
        assert_eq!(
            rpc_mock
                .get_block_info(hash)
                .await
                .unwrap()
                .block_data
                .previousblockhash
                .unwrap(),
            prev_hash
        );
        prev_hash = *hash;
    }
}

// Test default use case(without txs)
#[tokio::test]
async fn test_block_flow() {
    let (mocked_bitcoin_api, dummy_blockchain) = immitate_blockchain(BLOCKCHAIN_SIZE);
    let latest_blocks: VecDeque<_> = dummy_blockchain.iter().take(1).cloned().collect();

    let mut block_data_vec = Vec::new();
    for i in dummy_blockchain.iter().take(BLOCKCHAIN_SIZE).skip(1) {
        let block_data = mocked_bitcoin_api
            .get_block_info(&i.hash)
            .await
            .expect("Blockdata should exists");
        block_data_vec.push(block_data);
    }
    let mut tx_confirmator = init_tx_confirmator(mocked_bitcoin_api, latest_blocks, HashMap::new());

    for i in block_data_vec {
        assert!(
            tx_confirmator
                .handle_new_block(GetBlockTxResult {
                    block_data: i.block_data,
                    tx: vec![]
                })
                .await
                .is_ok()
        );
    }

    assert_eq!(
        tx_confirmator.latest_blocks.iter().last().unwrap().hash,
        dummy_blockchain.last().unwrap().hash
    );
    assert_eq!(
        tx_confirmator.latest_blocks.front().unwrap().hash,
        dummy_blockchain[BLOCKCHAIN_SIZE - 5].hash
    );
}

// Test chain reorg handling(without txs)
#[tokio::test]
async fn test_chain_reorg_handling() {
    let (mocked_bitcoin_api, dummy_blockchain) = immitate_blockchain(BLOCKCHAIN_SIZE);
    let mut latest_blocks: VecDeque<_> = dummy_blockchain
        .iter()
        .take(BLOCKCHAIN_SIZE - REORG_SIZE)
        .cloned()
        .collect();

    latest_blocks.extend([0; REORG_SIZE - 1].iter().map(|_| BlockInfo {
        hash: BlockHash::hash(&thread_rng().next_u64().to_be_bytes()),
        txs: vec![],
    }));

    // Check expected latest_blocks
    assert_eq!(latest_blocks.len(), BLOCKCHAIN_SIZE - 1);

    let mut confirmator = init_tx_confirmator(mocked_bitcoin_api, latest_blocks, HashMap::new());
    confirmator
        .handle_new_block(GetBlockTxResult {
            block_data: make_dummy_blockdata(
                dummy_blockchain.last().unwrap().hash,
                dummy_blockchain[BLOCKCHAIN_SIZE - 2].hash,
                BLOCKCHAIN_SIZE - 1,
            ),
            tx: vec![],
        })
        .await
        .unwrap();

    // Check, if reorg is really called. We check this by comparing latest_blocks size
    assert_eq!(
        confirmator.latest_blocks.len(),
        BLOCKCHAIN_SIZE - REORG_SIZE
    );

    // Check if last block was pushed to latest_blocks
    assert_eq!(
        confirmator.latest_blocks.back().unwrap().hash,
        dummy_blockchain[BLOCKCHAIN_SIZE - 1 - REORG_SIZE].hash
    )
}

// When confirmator contains less blocks, confirmator cannot handle reorg
#[tokio::test]
async fn test_confirmator_fails_long_reorg() {
    let (rpc_api, blockchain) = immitate_blockchain(BLOCKCHAIN_SIZE);
    let mut latest_blocks = VecDeque::new();
    latest_blocks.extend(blockchain.iter().take(BLOCKCHAIN_SIZE >> 1).cloned());
    let last_block_data = rpc_api
        .get_block_info(&blockchain.last().unwrap().hash)
        .await
        .unwrap()
        .block_data;
    let mut confirmator = init_tx_confirmator(rpc_api, latest_blocks, HashMap::new());

    assert!(
        confirmator
            .handle_new_block(GetBlockTxResult {
                block_data: last_block_data,
                tx: vec![]
            })
            .await
            .is_err()
    );
}
