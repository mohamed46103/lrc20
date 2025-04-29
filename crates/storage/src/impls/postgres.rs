use crate::traits::{
    IndexerNodeStorage, InventoryStorage, Lrc20NodeStorage, MempoolNodeStorage, SparkNodeStorage,
};

use async_trait::async_trait;
use sea_orm::{ConnectOptions, DatabaseConnection};

use sea_orm::{DatabaseTransaction, DbErr, TransactionTrait};
use std::time::Duration;
use tracing::log::LevelFilter;

#[derive(Debug, Clone)]
pub struct PgDatabase {
    conn: DatabaseConnection,
}

impl PgDatabase {
    pub async fn new(
        database_url: &str,
        logging: bool,
        max_connections: Option<u32>,
        min_connections: Option<u32>,
        connect_timeout: Option<Duration>,
    ) -> Result<Self, DbErr> {
        let mut opt = ConnectOptions::new(database_url);

        if let Some(max_connections) = max_connections {
            opt.max_connections(max_connections);
        }
        if let Some(min_connections) = min_connections {
            opt.min_connections(min_connections);
        }
        if let Some(connect_timeout) = connect_timeout {
            opt.connect_timeout(connect_timeout);
        }

        opt.sqlx_logging(logging)
            .sqlx_logging_level(LevelFilter::Trace)
            .sqlx_slow_statements_logging_settings(LevelFilter::Trace, Duration::from_millis(100));

        let conn = sea_orm::Database::connect(opt).await?;
        Ok(Self { conn })
    }
}

#[async_trait]
pub trait PgDatabaseConnectionManager {
    async fn conn(&self) -> DatabaseConnection;

    async fn tx(&self) -> Result<DatabaseTransaction, DbErr>;
}

#[async_trait]
impl PgDatabaseConnectionManager for PgDatabase {
    async fn conn(&self) -> DatabaseConnection {
        self.conn.to_owned()
    }

    async fn tx(&self) -> Result<DatabaseTransaction, DbErr> {
        self.conn.begin().await
    }
}

impl Lrc20NodeStorage for PgDatabase {}

impl SparkNodeStorage for PgDatabase {}

impl IndexerNodeStorage for PgDatabase {}

impl MempoolNodeStorage for PgDatabase {}

impl InventoryStorage for PgDatabase {}
