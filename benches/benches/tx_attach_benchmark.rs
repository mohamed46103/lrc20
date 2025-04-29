#[macro_use]
extern crate criterion;

use criterion::async_executor::FuturesExecutor;
use criterion::{BatchSize, Criterion, black_box};
use event_bus::{BusEvent, EventBus};
use eyre::WrapErr;
use lrc20_storage::PgDatabase;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use lrc20_tx_attach::GraphBuilder;
use lrc20_types::{ControllerMessage, GraphBuilderMessage};

use crate::tx_generator::TxGenerator;

mod tx_generator;

/// Amount of messages generated per one benchmark iteration
const MSG_AMOUNT: u32 = 10;
/// Amount of transactions generated per one message
const TXS_PER_MSG: u32 = 1;

const NODE_DATABASE_URL: &str = "postgresql://127.0.0.1:5432";

pub fn init_event_bus() -> EventBus {
    let mut event_bus = EventBus::default();

    event_bus.register::<ControllerMessage>(None);
    event_bus.register::<GraphBuilderMessage>(None);

    event_bus
}

fn new_messages(
    msg_amount: u32,
    txs_per_message: u32,
    generator: &mut TxGenerator,
) -> Vec<GraphBuilderMessage> {
    let mut messages = Vec::new();

    for _ in 0..msg_amount {
        let mut lrc20_txs = Vec::new();
        for _ in 0..txs_per_message {
            let lrc20_tx = generator.get_next_lrc20_tx();

            lrc20_txs.push(lrc20_tx);
        }
        messages.push(GraphBuilderMessage::CheckedTxs(lrc20_txs));
    }

    messages
}

async fn spawn_graph_builder(
    event_bus: &EventBus,
    lrc20_node_storage: PgDatabase,
    cancellation: CancellationToken,
) {
    let graph_builder = GraphBuilder::new(
        lrc20_node_storage,
        event_bus,
        Duration::from_secs(5),
        Duration::from_secs(10),
    );

    tokio::spawn(graph_builder.run(cancellation));
}

pub async fn send_messages<E: BusEvent + Clone + 'static>(event_bus: &EventBus, messages: Vec<E>) {
    for msg in messages {
        event_bus.send(msg.clone()).await;
    }
}

#[tokio::main]
async fn tx_attach_benchmark(c: &mut Criterion) {
    let event_bus = init_event_bus();

    let cancellation = CancellationToken::new();

    let lrc20_node_storage = PgDatabase::new(NODE_DATABASE_URL, false)
        .await
        .wrap_err("failed to initialize storage")
        .unwrap();

    spawn_graph_builder(&event_bus, lrc20_node_storage, cancellation).await;

    let mut tx_generator = TxGenerator::default();

    c.bench_function("tx attach benchmark", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || new_messages(MSG_AMOUNT, TXS_PER_MSG, &mut tx_generator),
            |messages| send_messages(&event_bus, black_box(messages)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, tx_attach_benchmark);
criterion_main!(benches);
