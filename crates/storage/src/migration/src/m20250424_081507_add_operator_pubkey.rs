use sea_orm_migration::prelude::*;

use crate::m20250312_143952_add_lrc20_tables::{
    OperatorSignature, SparkIssueData, SparkOutput, SparkTransaction, UserSignature,
};

#[derive(Iden)]
pub enum OperatorPubkey {
    Table,
    Id,
    TxHash,
    OperatorIdentityPubkey,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OperatorPubkey::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OperatorPubkey::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OperatorPubkey::TxHash).binary().not_null())
                    .col(
                        ColumnDef::new(OperatorPubkey::OperatorIdentityPubkey)
                            .binary()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(OperatorPubkey::Table, OperatorPubkey::TxHash)
                            .to(SparkTransaction::Table, SparkTransaction::TxHash)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .table(OperatorPubkey::Table)
                            .col(OperatorPubkey::TxHash)
                            .col(OperatorPubkey::OperatorIdentityPubkey)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(UserSignature::Table)
                    .drop_column(UserSignature::OwnerPubkey)
                    .add_column(ColumnDef::new(UserSignature::OperatorPublicKey).binary())
                    .add_column(
                        ColumnDef::new(UserSignature::Type).custom(Alias::new("signature_type")),
                    )
                    .add_column(
                        ColumnDef::new(UserSignature::Index)
                            .small_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_signature_tx_hash_signature")
                    .table(UserSignature::Table)
                    .col(UserSignature::TxHash)
                    .col(UserSignature::Signature)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(OperatorSignature::Table)
                    .modify_column(
                        ColumnDef::new(OperatorSignature::Signature)
                            .binary()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(SparkIssueData::Table)
                    .add_column(ColumnDef::new(SparkIssueData::OperatorPubkey).binary())
                    .add_column(
                        ColumnDef::new(SparkIssueData::SignatureType)
                            .custom(Alias::new("signature_type")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_user_signature_tx_hash_owner")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_spark_output_spend_txid_vout")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("idx_user_signature_owner_pubkey")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(OperatorPubkey::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(UserSignature::Table)
                    .add_column(
                        ColumnDef::new(UserSignature::OwnerPubkey)
                            .binary()
                            .not_null(),
                    )
                    .drop_column(UserSignature::OperatorPublicKey)
                    .drop_column(UserSignature::Type)
                    .drop_column(UserSignature::Index)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_signature_tx_hash_signature")
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(OperatorSignature::Table)
                    .modify_column(ColumnDef::new(OperatorSignature::Signature).binary())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(SparkIssueData::Table)
                    .drop_column(SparkIssueData::OperatorPubkey)
                    .drop_column(SparkIssueData::SignatureType)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_user_signature_tx_hash_owner")
                    .table(UserSignature::Table)
                    .col(UserSignature::TxHash)
                    .col(UserSignature::OwnerPubkey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_spark_output_spend_txid_vout")
                    .table(SparkOutput::Table)
                    .col(SparkOutput::SpendTxid)
                    .col(SparkOutput::SpendVout)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_user_signature_owner_pubkey")
                    .table(UserSignature::Table)
                    .col(UserSignature::OwnerPubkey)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
