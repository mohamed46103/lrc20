use crate::entities::indexer_state;

use bitcoin::hashes::Hash;

use crate::PgDatabaseConnectionManager;

use async_trait::async_trait;
use bitcoin::BlockHash;
use sea_orm::*;

use sea_orm::DbErr;

static INDEXER_STATE_ID: i32 = 1;

#[async_trait]
pub trait IndexerNodeStorage: PgDatabaseConnectionManager + Send + Sync + 'static {
    async fn get_last_indexed_block_hash(&self) -> Result<Option<BlockHash>, DbErr> {
        let Some(indexer_state) = indexer_state::Entity::find_by_id(INDEXER_STATE_ID)
            .one(&self.conn().await)
            .await?
        else {
            return Ok(None);
        };

        let Some(blockhash_bytes) = indexer_state.last_block_hash else {
            return Ok(None);
        };

        let blockhash = BlockHash::from_slice(&blockhash_bytes)
            .map_err(|_e| DbErr::Custom("Failed to deserialize block hash".into()))?;

        Ok(Some(blockhash))
    }

    async fn update_indexer_state(&self, blockhash: BlockHash) -> Result<(), DbErr> {
        let conn = self.conn().await;
        let indexer_state = indexer_state::Entity::find_by_id(INDEXER_STATE_ID)
            .one(&conn)
            .await?
            .ok_or(DbErr::RecordNotFound("Indexer state is missing".into()))?;

        let mut active_model: indexer_state::ActiveModel = indexer_state.into();

        active_model.last_block_hash = Set(Some(blockhash.to_byte_array().to_vec()));
        active_model.update(&conn).await?;

        Ok(())
    }
}
