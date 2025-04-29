use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Iden)]
enum SparkTransaction {
    Table,
    TxHash,
    OperationType,
    Status,
    Network,
    CreatedAt,
}

#[derive(Iden)]
enum SparkOutput {
    Table,
    SparkId,
    TxHash,
    Vout,
    TokenPubkey,
    OwnerPubkey,
    WithdrawalBondSats,
    WithdrawalLocktime,
    ExitScript,
    TokenAmount,
    RevocationPubkey,
    RevocationSecretKey,
    IsFrozen,
    WithdrawTxid,
    WithdrawVout,
    WithdrawBlockhash,
    SpendTxid,
    SpendVout,
}

#[derive(Iden)]
enum SparkBurn {
    Table,
    TxHash,
    Vout,
    TokenPubkey,
    Amount,
}

#[derive(Iden)]
enum OperatorSignature {
    Table,
    TxHash,
    OperatorIdentityPubkey,
    Signature,
    Type,
}

#[derive(Iden)]
enum UserSignature {
    Table,
    TxHash,
    OwnerPubkey,
    Signature,
}

#[derive(Iden)]
enum SparkIssueData {
    Table,
    TxHash,
    IssuerPubkey,
    Nonce,
    IssuerProvidedTimestamp,
    IssuerSignature,
    IssueAmount,
}

#[derive(Iden)]
enum SparkFreezeData {
    Table,
    TxHash,
    IssuerPubkey,
    UserPubkey,
    IssuerProvidedTimestamp,
    OperatorIdentityPubkey,
    ShouldUnfreeze,
    IssuerSignature,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("idx_spark_transaction_created_at")
                    .table(SparkTransaction::Table)
                    .col(SparkTransaction::CreatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_output_tx_hash_vout")
                    .table(SparkOutput::Table)
                    .col(SparkOutput::TxHash)
                    .col(SparkOutput::Vout)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_output_token_pubkey")
                    .table(SparkOutput::Table)
                    .col(SparkOutput::TokenPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_output_owner_pubkey")
                    .table(SparkOutput::Table)
                    .col(SparkOutput::OwnerPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_output_spend")
                    .table(SparkOutput::Table)
                    .col(SparkOutput::SpendTxid)
                    .col(SparkOutput::SpendVout)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_burn_tx_hash_vout")
                    .table(SparkBurn::Table)
                    .col(SparkBurn::TxHash)
                    .col(SparkBurn::Vout)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_burn_token_pubkey")
                    .table(SparkBurn::Table)
                    .col(SparkBurn::TokenPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_operator_signature_tx_hash_operator")
                    .table(OperatorSignature::Table)
                    .col(OperatorSignature::TxHash)
                    .col(OperatorSignature::OperatorIdentityPubkey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
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
                    .name("idx_user_signature_owner_pubkey")
                    .table(UserSignature::Table)
                    .col(UserSignature::OwnerPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_issue_data_issuer_pubkey")
                    .table(SparkIssueData::Table)
                    .col(SparkIssueData::IssuerPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_issue_data_timestamp")
                    .table(SparkIssueData::Table)
                    .col(SparkIssueData::IssuerProvidedTimestamp)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_freeze_data_issuer_pubkey")
                    .table(SparkFreezeData::Table)
                    .col(SparkFreezeData::IssuerPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_freeze_data_user_pubkey")
                    .table(SparkFreezeData::Table)
                    .col(SparkFreezeData::UserPubkey)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_spark_freeze_data_timestamp")
                    .table(SparkFreezeData::Table)
                    .col(SparkFreezeData::IssuerProvidedTimestamp)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_freeze_data_timestamp")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_freeze_data_user_pubkey")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_freeze_data_issuer_pubkey")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_issue_data_timestamp")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_issue_data_issuer_pubkey")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_signature_tx_hash_owner")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_operator_signature_tx_hash_operator")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(Index::drop().name("idx_spark_burn_token_pubkey").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx_spark_burn_tx_hash_vout").to_owned())
            .await?;

        manager
            .drop_index(Index::drop().name("idx_spark_output_spend").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_output_owner_pubkey")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_output_token_pubkey")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_output_tx_hash_vout")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_transaction_created_at")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_signature_owner_pubkey")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_spark_output_spend_txid_vout")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
