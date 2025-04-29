#[macro_use]
extern crate criterion;

use std::sync::Arc;
use std::time::Duration;

use bitcoin_client::MockRpcApi;
use criterion::async_executor::FuturesExecutor;
use criterion::{BatchSize, Criterion, black_box};
use event_bus::{BusEvent, EventBus};
use eyre::WrapErr;
use lrc20_storage::PgDatabase;
use tokio_util::sync::CancellationToken;

use lrc20_tx_check::TxChecker;
use lrc20_types::{ControllerMessage, GraphBuilderMessage, TxCheckerMessage};

use crate::tx_generator::TxGenerator;

mod common;
mod tx_generator;

/// Amount of messages generated per one benchmark iteration
const MSG_AMOUNT: u32 = 10;
/// Amount of transactions generated per one message
const TXS_PER_MSG: u32 = 1;

const NODE_DATABASE_URL: &str = "postgresql://127.0.0.1:5432";

fn new_messages(
    msg_amount: u32,
    txs_per_message: u32,
    generator: &mut TxGenerator,
    mut rpc_api: Arc<MockRpcApi>,
) -> Vec<TxCheckerMessage> {
    let mut messages = Vec::new();

    let rpc_api = common::mut_mock(&mut rpc_api);

    for _ in 0..msg_amount {
        let mut lrc20_txs = Vec::new();
        for _ in 0..txs_per_message {
            let lrc20_tx = generator.get_next_lrc20_tx();

            lrc20_txs.push((lrc20_tx.clone(), None));

            rpc_api
                .expect_get_raw_transaction()
                .returning(move |_, _| Ok(lrc20_tx.clone().bitcoin_tx));
        }
        messages.push(TxCheckerMessage::FullCheck(lrc20_txs))
    }

    messages
}

async fn spawn_tx_checker(
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

pub fn init_event_bus() -> EventBus {
    let mut event_bus = EventBus::default();

    event_bus.register::<GraphBuilderMessage>(None);
    event_bus.register::<ControllerMessage>(None);
    event_bus.register::<TxCheckerMessage>(None);

    event_bus
}

pub async fn send_messages<E: BusEvent + Clone + 'static>(event_bus: &EventBus, messages: Vec<E>) {
    for msg in messages {
        event_bus.send(msg.clone()).await;
    }
}

#[tokio::main]
async fn tx_check_benchmark(c: &mut Criterion) {
    let event_bus = init_event_bus();

    let lrc20_node_storage = PgDatabase::new(NODE_DATABASE_URL, false)
        .await
        .wrap_err("failed to initialize storage")
        .unwrap();

    let mut tx_generator = TxGenerator::default();
    let rpc_api = Arc::new(MockRpcApi::default());

    let cancellation = CancellationToken::new();

    spawn_tx_checker(
        &event_bus,
        lrc20_node_storage,
        cancellation,
        rpc_api.clone(),
    )
    .await
    .expect("failed to start tx checker pool");

    c.bench_function("tx check benchmark", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || new_messages(MSG_AMOUNT, TXS_PER_MSG, &mut tx_generator, rpc_api.clone()),
            |messages| send_messages(&event_bus, black_box(messages)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, tx_check_benchmark);
criterion_main!(benches);
