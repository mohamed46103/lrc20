#[macro_use]
extern crate criterion;

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Txid;
use bitcoin_client::MockRpcApi;
use criterion::async_executor::FuturesExecutor;
use criterion::{BatchSize, Criterion, black_box};
use event_bus::{BusEvent, EventBus};
use eyre::WrapErr;
use tokio_util::sync::CancellationToken;

use lrc20_controller::Controller;
use lrc20_p2p::client::handle::MockHandle;
use lrc20_storage::PgDatabase;
use lrc20_tx_attach::GraphBuilder;
use lrc20_tx_check::TxChecker;
use lrc20_types::messages::p2p::Inventory;
use lrc20_types::{
    ControllerMessage, ControllerP2PMessage, GraphBuilderMessage, Lrc20Transaction,
    TxCheckerMessage, TxConfirmMessage,
};

mod common;
mod tx_generator;

use crate::common::mut_mock;
use crate::tx_generator::TxGenerator;

/// Amount of messages generated per one benchmark iteration
const MSG_AMOUNT: u32 = 10;
/// Amount of transactions generated per one message
const TXS_PER_MSG: u32 = 1;
const INV_SHARING_INTERVAL: Duration = Duration::from_secs(5);
const MAX_INV_SIZE: usize = 100;

const DUMMY_SOCKET_ADDR: std::net::SocketAddr = std::net::SocketAddr::V4(
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 0),
);

const NODE_DATABASE_URL: &str = "postgresql://127.0.0.1:5432";

pub fn new_messages(
    msg_amount: u32,
    txs_per_message: u32,
    generator: &mut TxGenerator,
    mut rpc_api: Arc<MockRpcApi>,
) -> Vec<ControllerMessage> {
    let mut messages = Vec::new();

    let rpc_api = mut_mock(&mut rpc_api);

    for _ in 0..msg_amount {
        messages.append(&mut vec![
            ControllerMessage::InvalidTxs(gen_new_lrc20_tx_ids(txs_per_message, generator)),
            ControllerMessage::InitializeTxs(gen_new_lrc20_txs(1, generator).clone()),
            ControllerMessage::P2P(ControllerP2PMessage::Inv {
                inv: convert_to_inventory(gen_new_lrc20_tx_ids(txs_per_message, generator)),
                sender: DUMMY_SOCKET_ADDR,
            }),
            {
                let txs = gen_new_lrc20_txs(txs_per_message, generator);
                for tx in txs.clone() {
                    rpc_api
                        .expect_get_raw_transaction()
                        .returning(move |_, _| Ok(tx.clone().bitcoin_tx));
                }
                ControllerMessage::P2P(ControllerP2PMessage::Lrc20Tx {
                    txs,
                    sender: DUMMY_SOCKET_ADDR,
                })
            },
            ControllerMessage::P2P(ControllerP2PMessage::GetData {
                inv: convert_to_inventory(gen_new_lrc20_tx_ids(txs_per_message, generator)),
                sender: DUMMY_SOCKET_ADDR,
            }),
        ])
    }

    messages
}

fn gen_new_lrc20_txs(txs_per_message: u32, generator: &mut TxGenerator) -> Vec<Lrc20Transaction> {
    let mut lrc20_txs = Vec::new();
    for _ in 0..txs_per_message {
        lrc20_txs.push(generator.get_next_lrc20_tx());
    }
    lrc20_txs
}

fn gen_new_lrc20_tx_ids(txs_per_message: u32, generator: &mut TxGenerator) -> Vec<Txid> {
    let mut lrc20_txs = Vec::new();
    for _ in 0..txs_per_message {
        lrc20_txs.push(generator.get_next_lrc20_tx().bitcoin_tx.txid());
    }
    lrc20_txs
}

fn convert_to_inventory(tx_ids: Vec<Txid>) -> Vec<Inventory> {
    tx_ids.into_iter().map(Inventory::Ltx).collect()
}

pub fn init_event_bus() -> EventBus {
    let mut event_bus = EventBus::default();

    event_bus.register::<TxCheckerMessage>(None);
    event_bus.register::<TxConfirmMessage>(None);
    event_bus.register::<ControllerMessage>(None);
    event_bus.register::<GraphBuilderMessage>(None);

    event_bus
}

fn spawn_graph_builder(
    event_bus: &EventBus,
    node_storage: PgDatabase,
    cancellation: CancellationToken,
) {
    let graph_builder = GraphBuilder::new(
        node_storage,
        event_bus,
        Duration::from_secs(5),
        Duration::from_secs(10),
    );

    tokio::spawn(graph_builder.run(cancellation.clone()));
}

fn spawn_tx_checker(
    event_bus: &EventBus,
    lrc20_node_storage: PgDatabase,
    cancellation: CancellationToken,
    btc_client: Arc<MockRpcApi>,
) -> eyre::Result<()> {
    let tx_checker = TxChecker::new(
        event_bus.clone(),
        lrc20_node_storage,
        btc_client,
        false,
        Duration::from_secs(5),
        Duration::from_secs(10),
    );

    tokio::spawn(tx_checker.run(cancellation));
    Ok(())
}

fn spawn_controller(
    event_bus: &EventBus,
    lrc20_node_storage: PgDatabase,
    cancellation: CancellationToken,
) {
    let mut mocked_p2p = MockHandle::new();

    // Just expect all messages to be sent successfully
    mocked_p2p.expect_send_inv().times(..).returning(|_| Ok(()));
    mocked_p2p
        .expect_send_get_data()
        .times(..)
        .returning(|_, _| Ok(()));
    mocked_p2p.expect_ban_peer().times(..).returning(|_| Ok(()));

    let controller = Controller::new(event_bus, lrc20_node_storage, mocked_p2p)
        .set_inv_sharing_interval(INV_SHARING_INTERVAL)
        .set_max_inv_size(MAX_INV_SIZE);

    tokio::spawn(controller.run(cancellation));
}

pub async fn send_messages<E: BusEvent + Clone + 'static>(event_bus: &EventBus, messages: Vec<E>) {
    for msg in messages {
        event_bus.send(msg.clone()).await;
    }
}

#[tokio::main]
pub async fn tx_controller_benchmark(c: &mut Criterion) {
    let event_bus = init_event_bus();

    let lrc20_node_storage = PgDatabase::new(NODE_DATABASE_URL, false)
        .await
        .wrap_err("failed to initialize storage")
        .unwrap();

    let mut tx_generator = TxGenerator::default();

    let rpc_api = Arc::new(MockRpcApi::default());

    let cancellation = CancellationToken::new();

    spawn_graph_builder(&event_bus, lrc20_node_storage.clone(), cancellation.clone());

    spawn_tx_checker(
        &event_bus,
        lrc20_node_storage.clone(),
        cancellation.clone(),
        rpc_api.clone(),
    )
    .expect("failed to start tx checker pool");

    spawn_controller(&event_bus, lrc20_node_storage.clone(), cancellation.clone());

    c.bench_function("tx controller benchmark", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || new_messages(MSG_AMOUNT, TXS_PER_MSG, &mut tx_generator, rpc_api.clone()),
            |messages| send_messages(&event_bus, black_box(messages)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, tx_controller_benchmark);
criterion_main!(benches);
