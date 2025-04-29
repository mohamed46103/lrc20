use lrc20_types::Lrc20Transaction;
use once_cell::sync::Lazy;

use crate::check_transaction;

mod script_parser;

static VALID_MULTITOKEN_TRANSFER: Lazy<Lrc20Transaction> = Lazy::new(|| {
    serde_json::from_str::<Lrc20Transaction>(include_str!(
        "./assets/multitoken_valid_transfer.json"
    ))
    .expect("JSON was not well-formatted")
});

static VALID_SINGLETOKEN_PUBKEY_TRANSFER: Lazy<Lrc20Transaction> = Lazy::new(|| {
    serde_json::from_str::<Lrc20Transaction>(include_str!(
        "./assets/singletoken_valid_transfer.json"
    ))
    .expect("JSON was not well-formatted")
});

static VALID_SPARK_EXIT: Lazy<Lrc20Transaction> = Lazy::new(|| {
    serde_json::from_str::<Lrc20Transaction>(include_str!("./assets/spark_valid_exit.json"))
        .expect("JSON was not well-formatted")
});

static INVALID_MULTITOKEN_TRANSFER: Lazy<Lrc20Transaction> = Lazy::new(|| {
    serde_json::from_str::<Lrc20Transaction>(include_str!(
        "./assets/multitoken_invalid_transfer.json"
    ))
    .expect("JSON was not well-formatted")
});

static INVALID_SINGLETOKEN_PUBKEY_TRANSFER: Lazy<Lrc20Transaction> = Lazy::new(|| {
    serde_json::from_str::<Lrc20Transaction>(include_str!(
        "./assets/singletoken_invalid_transfer.json"
    ))
    .expect("JSON was not well-formatted")
});

#[tokio::test]
async fn test_tx_checker_validates_multitoken_transfer() {
    let result = check_transaction(&VALID_MULTITOKEN_TRANSFER);

    assert!(result.is_ok(), "expected the tx to pass the check");
}

#[tokio::test]
async fn test_tx_checker_validates_singletoken_pubkey_transfer() {
    let result = check_transaction(&VALID_SINGLETOKEN_PUBKEY_TRANSFER);

    assert!(result.is_ok(), "expected the tx to pass the check");
}

#[tokio::test]
async fn test_tx_checker_validates_spark_exit() {
    let result = check_transaction(&VALID_SPARK_EXIT);

    assert!(result.is_ok(), "expected the tx to pass the check");
}

#[tokio::test]
async fn test_tx_checker_fails_invalid_multitoken_transfer() {
    let result = check_transaction(&INVALID_MULTITOKEN_TRANSFER);

    assert!(result.is_err(), "expected the tx to fail the check");
}

#[tokio::test]
async fn test_tx_checker_fails_invalid_singletoken_pubkey_transfer() {
    let result = check_transaction(&INVALID_SINGLETOKEN_PUBKEY_TRANSFER);

    assert!(result.is_err(), "expected the tx to fail the check");
}
