#![doc = include_str!("../README.md")]

mod errors;
pub use errors::CheckError;

mod isolated_checks;
pub use isolated_checks::{check_p2tr_proof, check_transaction};

mod service;
pub use service::{TxChecker, check_spark_conservation_rules, check_spark_tx_finalization};

mod script_parser;

#[cfg(test)]
mod tests;
