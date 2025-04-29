use std::fmt::{self, Display, Formatter};
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::SystemTime;
use std::{net, time, vec};

use async_trait::async_trait;
use flume as chan;

use event_bus::{EventBus, typeid};
use lrc20_types::network::Network;
use lrc20_types::spark::TokenTransaction;
use lrc20_types::spark::signature::SparkSignatureData;
use lrc20_types::{
    ControllerMessage, Lrc20Transaction,
    messages::p2p::{Inventory, NetworkMessage},
};
use tokio_util::sync::CancellationToken;

use crate::{
    client::error::Error,
    client::handle,
    client::peer::Cache,
    client::service::Service,
    common::time::{AdjustedTime, RefClock},
    fsm::handler,
    fsm::handler::PeerId,
    fsm::handler::{Command, Limits, Peer},
    net::{NetReactor, NetWaker},
};

use super::boot_nodes::insert_boot_nodes;

/// A wrapper around a hostname / port representing an address to a peer.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PeerAddr {
    pub hostname: String,
    pub port: u16,
}

impl PeerAddr {
    /// Create a new PeerAddr from a hostname and port.
    pub fn new(hostname: String, port: u16) -> Self {
        Self { hostname, port }
    }
}

impl Display for PeerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.hostname, self.port)
    }
}

impl FromStr for PeerAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let hostname = parts
            .next()
            .ok_or_else(|| Error::InvalidAddress {
                address: s.to_string(),
                description: "missing hostname".to_string(),
            })?
            .to_string();
        let port = parts
            .next()
            .ok_or_else(|| Error::InvalidAddress {
                address: s.to_string(),
                description: "missing port".to_string(),
            })?
            .parse::<u16>()
            .map_err(|_| Error::InvalidAddress {
                address: s.to_string(),
                description: "invalid port".to_string(),
            })?;

        Ok(PeerAddr::new(hostname, port))
    }
}

impl TryFrom<PeerAddr> for vec::IntoIter<SocketAddr> {
    type Error = Error;

    fn try_from(value: PeerAddr) -> Result<Self, Self::Error> {
        format!("{}:{}", value.hostname, value.port)
            .to_socket_addrs()
            .map_err(|err| Error::InvalidAddress {
                address: format!("{}", value),
                description: format!("{:?}", err),
            })
    }
}

/// P2P client configuration.
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Bitcoin network.
    pub network: Network,
    /// Bootstrap peers to which the client should connect, represented as host/port pairs.
    pub connect: Vec<PeerAddr>,
    /// Client listen address.
    pub listen: SocketAddr,
    /// User agent string.
    pub user_agent: &'static str,
    /// Configured limits (inbound/outbound connections).
    pub limits: Limits,
}

impl P2PConfig {
    /// Create a new configuration for the given network.
    pub fn new(
        network: Network,
        listen: SocketAddr,
        connect: Vec<PeerAddr>,
        max_inb: usize,
        max_outb: usize,
    ) -> Self {
        Self {
            network,
            limits: Limits {
                max_outbound_peers: max_outb,
                max_inbound_peers: max_inb,
            },
            listen,
            connect,
            ..Self::default()
        }
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            connect: Vec::new(),
            listen: ([0, 0, 0, 0], 0).into(),
            user_agent: handler::USER_AGENT,
            limits: Limits::default(),
        }
    }
}

/// Runs a pre-loaded client.
pub struct P2PClient<R: NetReactor> {
    handle: Handle<R::Waker>,
    service: Service<Cache, RefClock<AdjustedTime<SocketAddr>>>,
    listen: SocketAddr,
    commands: chan::Receiver<Command>,
    reactor: R,
}

impl<R: NetReactor> P2PClient<R> {
    /// Create a new client.
    pub fn new(config: &mut P2PConfig, full_event_bus: &EventBus) -> Result<Self, Error> {
        let (commands_tx, commands_rx) = chan::unbounded::<Command>();

        let (listening_send, listening) = chan::bounded(1);
        let reactor = <R as NetReactor>::new(listening_send)?;

        let event_bus = full_event_bus
            .extract(&typeid![ControllerMessage], &typeid![])
            .expect("event channels must be presented");

        let local_time = SystemTime::now().into();
        let clock = AdjustedTime::<SocketAddr>::new(local_time);
        let rng = fastrand::Rng::new();

        insert_boot_nodes(config);

        let p2p_service = Service::new(
            Cache::new(),
            RefClock::from(clock),
            rng,
            config.clone(),
            &event_bus,
        );

        let listen = config.listen;

        let handle = Handle {
            commands: commands_tx,
            waker: reactor.waker(),
            timeout: time::Duration::from_secs(60),
            listening,
        };

        Ok(P2PClient {
            handle,
            listen,
            commands: commands_rx,
            reactor,
            service: p2p_service,
        })
    }

    /// Run a pre-loaded p2p client.
    pub async fn run(mut self, cancellation: CancellationToken) {
        // Block the P2P until the Start command is received.
        loop {
            let cmd = self
                .commands
                .recv_async()
                .await
                .expect("P2pClient handle dropped");

            // Omit all the commands but Start.
            if !matches!(cmd, Command::Start) {
                tracing::debug!("Received unexpected command: {:?}", cmd);
                continue;
            }

            tracing::debug!("Unblocking the P2P");
            break;
        }

        let result = self
            .reactor
            .run(&self.listen, self.service, self.commands, cancellation)
            .await;

        if let Err(e) = result {
            tracing::error!("P2P is down. P2P client run error: {}", e);
        }
    }

    /// Create a new handle to communicate with the client.
    pub fn handle(&self) -> Handle<R::Waker> {
        self.handle.clone()
    }
}

#[derive(Clone)]
pub struct Handle<W: NetWaker> {
    pub commands: chan::Sender<Command>,
    pub waker: W,
    pub timeout: time::Duration,
    pub listening: chan::Receiver<net::SocketAddr>,
}

impl<W: NetWaker> Handle<W> {
    /// Send a command to the command channel, and wake up the event loop.
    async fn _command(&self, cmd: Command) -> Result<(), handle::Error> {
        if self.commands.send_async(cmd).await.is_err() {
            return Err(handle::Error::Command);
        }
        self.waker.wake()?;

        Ok(())
    }
}

#[async_trait]
impl<W: NetWaker> handle::Handle for Handle<W> {
    async fn command(&self, cmd: Command) -> Result<(), handle::Error> {
        self._command(cmd).await
    }

    async fn start(&self) -> Result<(), handle::Error> {
        self.command(Command::Start).await?;

        Ok(())
    }

    async fn broadcast(
        &self,
        msg: NetworkMessage,
        predicate: fn(Peer) -> bool,
    ) -> Result<Vec<net::SocketAddr>, handle::Error> {
        let (transmit, receive) = chan::bounded(1);
        self.command(Command::Broadcast(msg, predicate, transmit))
            .await?;

        match receive.recv_async().await {
            Ok(addr) => Ok(addr),
            Err(_) => Err(handle::Error::Timeout),
        }
    }

    async fn query(&self, msg: NetworkMessage) -> Result<Option<net::SocketAddr>, handle::Error> {
        let (transmit, receive) = chan::bounded::<Option<SocketAddr>>(1);
        self.command(Command::Query(msg, transmit)).await?;

        match receive.recv_async().await {
            Ok(addr) => Ok(addr),
            Err(_) => Err(handle::Error::Timeout),
        }
    }

    async fn send_inv(&self, inv: Vec<Inventory>) -> Result<(), handle::Error> {
        self.command(Command::SendInv(inv)).await?;

        Ok(())
    }

    async fn send_get_data(&self, inv: Vec<Inventory>, addr: PeerId) -> Result<(), handle::Error> {
        self.command(Command::SendGetData(inv, addr)).await?;

        Ok(())
    }

    async fn send_lrc20_txs(
        &self,
        txs: Vec<Lrc20Transaction>,
        addr: PeerId,
    ) -> Result<(), handle::Error> {
        self.command(Command::SendLrc20Transactions(txs, addr))
            .await?;

        Ok(())
    }

    async fn send_spark_txs(
        &self,
        txs: Vec<TokenTransaction>,
        addr: PeerId,
    ) -> Result<(), handle::Error> {
        self.command(Command::SendSparkTransactions(txs, addr))
            .await?;

        Ok(())
    }

    async fn send_spark_signatures(
        &self,
        signatures: Vec<SparkSignatureData>,
        addr: PeerId,
    ) -> Result<(), handle::Error> {
        self.command(Command::SendSparkSignatures(signatures, addr))
            .await?;

        Ok(())
    }

    async fn ban_peer(&self, addr: SocketAddr) -> Result<(), handle::Error> {
        self.command(Command::BanPeer(addr)).await
    }
}
