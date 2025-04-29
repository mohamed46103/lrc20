use std::sync::Arc;
use std::time::Duration;

use crate::config::NodeConfig;
use bitcoin_client::BitcoinRpcClient;
use event_bus::EventBus;
use eyre::Ok;
use lrc20_controller::Controller;
use lrc20_indexers::{AnnouncementsIndexer, BitcoinBlockIndexer, ConfirmationIndexer, RunParams};
use tokio::select;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};

use lrc20_p2p::{
    client::{Handle, P2PClient},
    net::{ReactorTcp, Waker},
};
use lrc20_rpc_server::ServerConfig;
use lrc20_storage::PgDatabase;
use lrc20_tx_attach::{GraphBuilder, SparkGraphBuilder};
use lrc20_tx_check::TxChecker;
use lrc20_tx_confirm::TxConfirmator;
use lrc20_types::messages::SparkGraphBuilderMessage;
use lrc20_types::{
    ControllerMessage, GraphBuilderMessage, IndexerMessage, TxCheckerMessage, TxConfirmMessage,
};

/// Default size of the channel for the event bus.
const DEFAULT_CHANNEL_SIZE: usize = 1000;
/// The limit of time to wait for the node to shutdown.
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Node encapsulate node service's start
pub struct Node {
    config: NodeConfig,
    event_bus: EventBus,
    lrc20_node_storage: PgDatabase,
    btc_client: Arc<BitcoinRpcClient>,
    cancelation: CancellationToken,
    validate_announcement: bool,

    pub(crate) task_tracker: TaskTracker,
}

impl Node {
    pub async fn new(config: NodeConfig) -> eyre::Result<Self> {
        let event_bus = Self::init_event_bus();
        let validate_announcement = config.storage.validate_announcements;

        let btc_client = Arc::new(
            BitcoinRpcClient::new(
                config.bnode.auth().clone(),
                config.bnode.url.clone(),
                config.bnode.timeout,
            )
            .await?,
        );

        let lrc20_node_storage = PgDatabase::new(
            &config.storage.database_url,
            config.storage.logging.unwrap_or_default(),
            config.storage.max_connections,
            config.storage.min_connections,
            config.storage.connect_timeout,
        )
        .await?;

        Ok(Self {
            config,
            event_bus,
            lrc20_node_storage,
            btc_client,
            cancelation: CancellationToken::new(),
            task_tracker: TaskTracker::new(),
            validate_announcement,
        })
    }

    /// Wait for the signal from any node's service about the cancellation.
    pub async fn cancelled(&self) {
        self.cancelation.cancelled().await
    }

    /// The order of service starting is important if you want to index blocks first and then start
    /// listen to inbound messages.
    pub async fn run(&self) -> eyre::Result<()> {
        self.spawn_graph_builder();
        self.spawn_spark_graph_builder();
        self.spawn_tx_checker()?;
        self.spawn_tx_confirmator();

        let p2p_handle = self.spawn_p2p()?;
        self.spawn_controller(p2p_handle).await?;
        self.spawn_indexer().await?;

        self.spawn_rpc();

        self.task_tracker.close();

        Ok(())
    }

    fn spawn_p2p(&self) -> eyre::Result<Handle<Waker>> {
        let p2p_client_runner = P2PClient::<ReactorTcp>::new(
            &mut self.config.p2p.to_client_config(self.config.network)?,
            &self.event_bus,
        )
        .expect("P2P client must be successfully created");

        let handle = p2p_client_runner.handle();

        self.task_tracker
            .spawn(p2p_client_runner.run(self.cancelation.clone()));

        Ok(handle)
    }

    async fn spawn_controller(&self, handle: Handle<Waker>) -> eyre::Result<()> {
        let mut controller =
            Controller::new(&self.event_bus, self.lrc20_node_storage.clone(), handle)
                .set_inv_sharing_interval(Duration::from_millis(
                    self.config.controller.inv_sharing_interval,
                ))
                .set_max_inv_size(self.config.controller.max_inv_size);

        controller.handle_mempool_txs().await?;

        self.task_tracker
            .spawn(controller.run(self.cancelation.clone()));

        Ok(())
    }

    fn spawn_graph_builder(&self) {
        let config = &self.config.graph_builder;
        let graph_builder = GraphBuilder::new(
            self.lrc20_node_storage.clone(),
            &self.event_bus,
            config.cleanup_period,
            config.tx_outdated_duration,
        );

        self.task_tracker
            .spawn(graph_builder.run(self.cancelation.clone()));
    }

    fn spawn_spark_graph_builder(&self) {
        let config = &self.config.graph_builder;
        let graph_builder = SparkGraphBuilder::new(
            self.lrc20_node_storage.clone(),
            &self.event_bus,
            config.cleanup_period,
            config.tx_outdated_duration,
        );

        self.task_tracker
            .spawn(graph_builder.run(self.cancelation.clone()));
    }

    fn spawn_tx_checker(&self) -> eyre::Result<()> {
        let config = &self.config.graph_builder;
        let tx_checker = TxChecker::new(
            self.event_bus.clone(),
            self.lrc20_node_storage.clone(),
            self.btc_client.clone(),
            self.validate_announcement,
            config.cleanup_period,
            config.tx_outdated_duration,
        );

        self.task_tracker
            .spawn(tx_checker.run(self.cancelation.clone()));

        Ok(())
    }

    fn spawn_tx_confirmator(&self) {
        let tx_confirmator = TxConfirmator::new(
            &self.event_bus,
            self.btc_client.clone(),
            self.config.indexer.max_confirmation_time,
            self.config.indexer.clean_up_interval,
            self.config.indexer.confirmations_number,
        );

        self.task_tracker
            .spawn(tx_confirmator.run(self.cancelation.clone()));
    }

    fn spawn_rpc(&self) {
        let json_rpc_address = self.config.rpc.address.to_string();
        let grpc_address = self.config.rpc.grpc_address.to_string();
        let tls_config = self.config.rpc.tls_config.clone();
        let max_items_per_request = self.config.rpc.max_items_per_request;
        let max_request_size_kb = self.config.rpc.max_request_size_kb;
        let page_size = self.config.storage.tx_per_page;

        self.task_tracker.spawn(lrc20_rpc_server::run_server(
            ServerConfig {
                json_rpc_address,
                grpc_address,
                tls_config,
                max_items_per_request,
                max_request_size_kb,
                page_size,
            },
            self.lrc20_node_storage.clone(),
            self.event_bus.clone(),
            self.btc_client.clone(),
            self.cancelation.clone(),
            self.config.indexer.enforce_announcements.unwrap_or(true),
        ));
    }

    async fn spawn_indexer(&self) -> eyre::Result<()> {
        let mut indexer = BitcoinBlockIndexer::new(
            self.btc_client.clone(),
            self.lrc20_node_storage.clone(),
            &self.event_bus,
            self.config.network,
            self.config.indexer.liveness_period,
        );

        indexer.add_subindexer(AnnouncementsIndexer::new(
            &self.event_bus,
            self.config.network,
        ));
        indexer.add_subindexer(ConfirmationIndexer::new(&self.event_bus));

        let restart_interval = self.config.indexer.restart_interval;
        let mut current_attempt = 1;
        while let Err(err) = indexer
            .init(
                self.config.indexer.clone().into(),
                self.config.indexer.blockloader.clone(),
                self.btc_client.clone(),
                self.config.indexer.confirmations_number as usize,
                self.cancelation.clone(),
            )
            .await
        {
            if self.cancelation.is_cancelled() {
                return Ok(());
            }

            if current_attempt >= self.config.indexer.max_restart_attempts {
                self.cancelation.cancel();
                return Err(err);
            }

            current_attempt += 1;
            error!(
                %err,
                "Failed to init the indexer. Trying again in {} secs",
                restart_interval.as_secs()
            );
            tokio::time::sleep(restart_interval).await;
        }

        self.task_tracker.spawn(indexer.run(
            RunParams {
                polling_period: self.config.indexer.polling_period,
            },
            self.cancelation.clone(),
        ));

        Ok(())
    }

    fn init_event_bus() -> EventBus {
        let mut event_bus = EventBus::default();
        event_bus.register::<TxCheckerMessage>(Some(DEFAULT_CHANNEL_SIZE));
        event_bus.register::<GraphBuilderMessage>(Some(DEFAULT_CHANNEL_SIZE));
        event_bus.register::<SparkGraphBuilderMessage>(Some(DEFAULT_CHANNEL_SIZE));
        event_bus.register::<ControllerMessage>(Some(DEFAULT_CHANNEL_SIZE));
        event_bus.register::<TxConfirmMessage>(Some(DEFAULT_CHANNEL_SIZE));
        event_bus.register::<IndexerMessage>(Some(DEFAULT_CHANNEL_SIZE));

        event_bus
    }

    pub async fn shutdown(&self) {
        info!("Shutting down node, finishing received requests...");

        self.cancelation.cancel();

        let timeout = self
            .config
            .shutdown_timeout
            .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_SECS);

        select! {
            // Wait until all tasks are finished
            _ = self.task_tracker.wait() => {},
            // Or wait for and exit by timeout
            _ = sleep(Duration::from_secs(timeout)) => {
                info!("Shutdown timeout reached, exiting...");
            },
        }
    }
}
