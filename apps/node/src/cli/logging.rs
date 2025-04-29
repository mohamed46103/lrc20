use std::{cmp::min, sync::Mutex, time::Duration};

use eyre::eyre;
use serde::Serialize;
use serde_json::{Value, to_value};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};
use tracing::{Event, Instrument, Level, Subscriber, info_span};
use tracing_subscriber::{
    EnvFilter,
    fmt::format::{DefaultVisitor, Writer},
    layer::Layer,
    prelude::*,
};

pub fn init(level: Level, tcp_log_address: Option<String>) -> eyre::Result<()> {
    let stdout_filter = new_env_filter(level, "RUST_LOG")?;
    let tcp_log_filter = new_env_filter(level, "RUST_LOG_TCP")?;

    let tcp_log = if let Some(address) = tcp_log_address {
        let writer = TCPWriter::new(address)?;

        let tcp_log = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_writer(Mutex::new(writer))
            .with_filter(tcp_log_filter);

        Some(tcp_log)
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(Lrc20Tracer.with_filter(stdout_filter))
        .with(tcp_log)
        .try_init()?;

    Ok(())
}

fn new_env_filter(level: Level, env_var: &str) -> eyre::Result<EnvFilter> {
    let default_directives = [
        format!("{}", level),
        "hyper_util=info".to_string(),
        "hyper=info".to_string(),
        "h2=info".to_string(),
        "sqlx=info".to_string(),
        format!("lrc20_indexers={}", level),
        format!("lrc20_controller={}", level),
        format!("lrc20_rpc_server={}", level),
        format!("lrc20_network={}", level),
        format!("lrc20_tx_attach={}", level),
        format!("lrc20_tx_check={}", level),
        format!("lrc20_p2p={}", level),
    ];

    let env_directives = std::env::var(env_var).ok();

    let filter = match env_directives {
        Some(env) => {
            let mut filter = EnvFilter::new("");
            for directive in default_directives {
                filter = filter.add_directive(
                    directive
                        .parse()
                        .map_err(|_| eyre!("Invalid directive: {}", directive))?,
                )
            }

            // Add the directives from the environment variable, which should override all of our
            // defaults since they're being added last.
            if !env.is_empty() {
                for directive in env.split(',') {
                    filter = filter.add_directive(
                        directive
                            .parse()
                            .map_err(|_| eyre!("Invalid directive: {}", directive))?,
                    )
                }
            }

            filter
        }
        None => EnvFilter::new(default_directives.join(",")),
    };

    Ok(filter)
}

struct TCPWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

impl TCPWriter {
    pub(crate) fn new(address: String) -> eyre::Result<Self> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        let kubernetes = KubernetesMetadata {
            container: NameMetadata {
                name: std::env::var("CONTAINER_NAME").unwrap_or_default(),
            },
            statefulset: NameMetadata {
                name: std::env::var("STATEFULSET_NAME").unwrap_or_default(),
            },
            namespace: std::env::var("POD_NAMESPACE").unwrap_or_default(),
            node: NameMetadata {
                name: std::env::var("NODE_NAME").unwrap_or_default(),
            },
            pod: PodMetadata {
                name: std::env::var("POD_NAME").unwrap_or_default(),
                ip: std::env::var("POD_IP").unwrap_or_default(),
            },
        };
        tokio::spawn(
            async move {
                let mut socket = None;
                let mut delay = 1000;

                while let Some(message) = rx.recv().await {
                    if socket.is_none() {
                        socket =
                            match timeout(Duration::from_millis(1000), TcpStream::connect(&address))
                                .await
                            {
                                Ok(result) => match result {
                                    Ok(s) => {
                                        delay = 1000;
                                        Some(s)
                                    }
                                    Err(e) => {
                                        eprintln!("[tcplog] Connect {} failed: {:?}", address, e);
                                        None
                                    }
                                },
                                Err(e) => {
                                    eprintln!("[tcplog] Connect {} failed: {:?}", address, e);
                                    None
                                }
                            }
                    }

                    match socket.as_mut() {
                        Some(s) => {
                            let mut v: Value = serde_json::from_slice(&message)
                                .map_err(|err| {
                                    eprintln!(
                                        "[tcplog] Deserialize of message '{}', failed: {:?}",
                                        String::from_utf8_lossy(message.as_slice()),
                                        err
                                    )
                                })
                                .unwrap_or_default();
                            v["kubernetes"] = to_value(&kubernetes)
                                .map_err(|err| {
                                    eprintln!(
                                        "[tcplog] Failed to serialize kubernetes metadata: {:?}",
                                        err
                                    )
                                })
                                .unwrap_or_default();
                            let mut payload = v.to_string();
                            payload.push('\n');
                            socket = match s.write_all(payload.as_bytes()).await {
                                Ok(_) => socket,
                                Err(e) => {
                                    eprintln!("[tcplog] Write failed: {:?}", e);
                                    None
                                }
                            }
                        }
                        None => {
                            sleep(Duration::from_millis(delay)).await;
                            delay = min(60000, delay * 3 / 2);
                        }
                    }
                }
            }
            .instrument(info_span!("tcplog")),
        );
        Ok(Self { tx })
    }
}

impl std::io::Write for TCPWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = self.tx.try_send(buf.to_vec()).inspect_err(|err| {
            eprintln!("[tcplog] Queue send failed: {}", err);
        });

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct NameMetadata {
    name: String,
}

#[derive(Serialize)]
struct PodMetadata {
    name: String,
    ip: String,
}

#[derive(Serialize)]
struct KubernetesMetadata {
    container: NameMetadata,
    statefulset: NameMetadata,
    namespace: String,
    node: NameMetadata,
    pod: PodMetadata,
}

pub struct Lrc20Tracer;

impl<S> Layer<S> for Lrc20Tracer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let target = match event.metadata().level() {
            &Level::INFO | &Level::WARN | &Level::ERROR => event
                .metadata()
                .target()
                .split("::")
                .last()
                .unwrap_or_default(),
            _ => event.metadata().target(),
        };

        print!(
            "[{}] {} {}: ",
            chrono::offset::Local::now().format("%Y-%m-%d %H:%M:%S"),
            event.metadata().level(),
            target,
        );

        let mut message = String::new();

        event.record(&mut DefaultVisitor::new(Writer::new(&mut message), true));

        println!("{}", message);
    }
}
