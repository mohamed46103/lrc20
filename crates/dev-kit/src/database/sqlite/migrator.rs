use sqlx::migrate::Migrator;

pub(super) static MIGRATOR: Migrator = sqlx::migrate!("./src/database/sqlite/migrations");
