use lrc20_types::spark::TokenTransactionStatus;

use crate::entities::sea_orm_active_enums::Status as TokenTransactionEntityStatus;

impl From<TokenTransactionStatus> for TokenTransactionEntityStatus {
    fn from(tx_status: TokenTransactionStatus) -> Self {
        match tx_status {
            TokenTransactionStatus::Started => TokenTransactionEntityStatus::Started,
            TokenTransactionStatus::Signed => TokenTransactionEntityStatus::Signed,
            TokenTransactionStatus::Finalized => TokenTransactionEntityStatus::Finalized,
        }
    }
}

impl From<TokenTransactionEntityStatus> for TokenTransactionStatus {
    fn from(tx_status: TokenTransactionEntityStatus) -> Self {
        match tx_status {
            TokenTransactionEntityStatus::Started => TokenTransactionStatus::Started,
            TokenTransactionEntityStatus::Signed => TokenTransactionStatus::Signed,
            TokenTransactionEntityStatus::Finalized => TokenTransactionStatus::Finalized,
        }
    }
}
