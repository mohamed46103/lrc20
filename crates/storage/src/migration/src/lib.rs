pub use sea_orm_migration::prelude::*;

mod m20250312_143952_add_lrc20_tables;
mod m20250312_143954_add_spark_indexes;
mod m20250424_081507_add_operator_pubkey;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250312_143952_add_lrc20_tables::Migration),
            Box::new(m20250312_143954_add_spark_indexes::Migration),
            Box::new(m20250424_081507_add_operator_pubkey::Migration),
        ]
    }
}
