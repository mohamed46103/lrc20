use crate::types::{Utxo, WeightedUtxo};
use bdk::Error;
use bitcoin::Script;
use lrc20_receipts::TokenPubkey;

/// Default coin selection algorithm used by transaction buileder if not
/// overridden
pub type DefaultCoinSelectionAlgorithm = Lrc20LargestFirstCoinSelection;

/// Result of a successful coin selection
#[derive(Debug)]
pub struct LRC20CoinSelectionResult {
    /// List of outputs selected for use as inputs
    pub selected: Vec<Utxo>,
    /// Remaining amount after deducting fees and outgoing outputs
    pub amount: u128,
}

impl LRC20CoinSelectionResult {
    /// The total value of the inputs selected.
    pub fn selected_amount(&self) -> u128 {
        self.selected
            .iter()
            .map(|u| u.lrc20_txout().receipt.token_amount.amount)
            .sum()
    }

    /// The total value of the inputs selected from the local wallet.
    pub fn local_selected_amount(&self) -> u128 {
        self.selected
            .iter()
            .map(|u| u.lrc20_txout().receipt.token_amount.amount)
            .sum()
    }
}

/// Trait for generalized coin selection algorithms
///
/// This trait can be implemented to make the [`Wallet`](crate::wallet::Wallet) use a customized coin
/// selection algorithm when it creates transactions.
pub trait LRC20CoinSelectionAlgorithm: core::fmt::Debug {
    /// Perform the coin selection
    ///
    /// - `database`: a reference to the wallet's database that can be used to lookup additional
    ///               details for a specific UTXO
    /// - `required_utxos`: the utxos that must be spent regardless of `target_amount` with their
    ///                     weight cost
    /// - `optional_utxos`: the remaining available utxos to satisfy `target_amount` with their
    ///                     weight cost
    /// - `fee_rate`: fee rate to use
    /// - `target_amount`: the outgoing amount in satoshis and the fees already
    ///                    accumulated from added outputs and transaction’s header.
    /// - `drain_script`: the script to use in case of change
    fn coin_select(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        optional_utxos: Vec<WeightedUtxo>,
        target_amount: u128,
        drain_script: &Script,
        target_token: TokenPubkey,
    ) -> Result<LRC20CoinSelectionResult, Error>;
}

/// Simple and dumb coin selection
///
/// This coin selection algorithm sorts the available UTXOs by value and then picks them starting
/// from the largest ones until the required amount is reached.
/// Simple and dumb coin selection
///
/// This coin selection algorithm sorts the available UTXOs by value and then picks them starting
/// from the largest ones until the required amount is reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lrc20LargestFirstCoinSelection;

impl LRC20CoinSelectionAlgorithm for Lrc20LargestFirstCoinSelection {
    fn coin_select(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        mut optional_utxos: Vec<WeightedUtxo>,
        target_amount: u128,
        drain_script: &Script,
        target_token_pubkey: TokenPubkey,
    ) -> Result<LRC20CoinSelectionResult, Error> {
        tracing::debug!("target_amount = `{}`", target_amount);

        // Filter UTXOs based on the target token.
        optional_utxos.retain(|wu| {
            wu.utxo.lrc20_txout().receipt.token_pubkey == target_token_pubkey
                && !wu.utxo.lrc20_txout().script_pubkey.is_op_return()
        });

        // We put the "required UTXOs" first and make sure the optional UTXOs are sorted,
        // initially smallest to largest, before being reversed with `.rev()`.
        let utxos = {
            optional_utxos
                .sort_unstable_by_key(|wu| wu.utxo.lrc20_txout().receipt.token_amount.amount); // Sorting by amount now
            required_utxos
                .into_iter()
                .map(|utxo| (true, utxo))
                .chain(optional_utxos.into_iter().rev().map(|utxo| (false, utxo)))
        };

        select_sorted_utxos(utxos, target_amount, drain_script)
    }
}

/// OldestFirstCoinSelection always picks the utxo with the smallest blockheight to add to the selected coins next
///
/// This coin selection algorithm sorts the available UTXOs by blockheight and then picks them starting
/// from the oldest ones until the required amount is reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct LRC20OldestFirstCoinSelection;

impl LRC20CoinSelectionAlgorithm for LRC20OldestFirstCoinSelection {
    fn coin_select(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        mut optional_utxos: Vec<WeightedUtxo>,
        target_amount: u128,
        drain_script: &Script,
        target_token_pubkey: TokenPubkey,
    ) -> Result<LRC20CoinSelectionResult, Error> {
        // We put the "required UTXOs" first and make sure the optional UTXOs are sorted from
        // oldest to newest according to blocktime
        // For utxo that doesn't exist in DB, they will have lowest priority to be selected
        let utxos = {
            optional_utxos
                .retain(|wu| wu.utxo.lrc20_txout().receipt.token_pubkey == target_token_pubkey);

            required_utxos
                .into_iter()
                .map(|utxo| (true, utxo))
                .chain(optional_utxos.into_iter().map(|utxo| (false, utxo)))
        };

        select_sorted_utxos(utxos, target_amount, drain_script)
    }
}

fn select_sorted_utxos(
    utxos: impl Iterator<Item = (bool, WeightedUtxo)>,
    target_amount: u128,
    _drain_script: &Script,
) -> Result<LRC20CoinSelectionResult, Error> {
    let mut lrc20_amount = 0;
    let selected = utxos
        .scan(
            &mut lrc20_amount,
            |lrc20_amount, (must_use, weighted_utxo)| {
                if must_use || **lrc20_amount < target_amount {
                    **lrc20_amount += weighted_utxo.utxo.lrc20_txout().receipt.token_amount.amount;
                    Some(weighted_utxo.utxo)
                } else {
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    Ok(LRC20CoinSelectionResult {
        selected,
        amount: lrc20_amount,
    })
}

#[cfg(test)]
mod test {
    use bitcoin::{OutPoint, ScriptBuf};
    use core::str::FromStr;
    use lrc20_receipts::{Receipt, TokenAmount};

    use super::*;
    use crate::types::*;

    // n. of items on witness (1WU) + signature len (1WU) + signature and sighash (72WU)
    // + pubkey len (1WU) + pubkey (33WU) + script sig len (1 byte, 4WU)
    const P2WPKH_SATISFACTION_SIZE: usize = 1 + 1 + 72 + 1 + 33 + 4;

    const FEE_AMOUNT: u64 = 50;

    fn utxo(
        satoshis: u64,
        lrc20_amount: u128,
        token: bitcoin::PublicKey,
        index: u32,
        is_spark: bool,
    ) -> WeightedUtxo {
        assert!(index < 10);
        let outpoint = OutPoint::from_str(&format!(
            "000000000000000000000000000000000000000000000000000000000000000{}:0",
            index
        ))
        .unwrap();
        WeightedUtxo {
            satisfaction_weight: P2WPKH_SATISFACTION_SIZE,
            utxo: Utxo::Lrc20(Lrc20Utxo {
                outpoint,
                txout: Lrc20TxOut {
                    satoshis,
                    script_pubkey: ScriptBuf::new(),
                    receipt: Receipt {
                        token_amount: TokenAmount::from(lrc20_amount),
                        token_pubkey: token.inner.into(),
                    },
                    is_spark,
                },
                keychain: KeychainKind::External,
                is_spent: false,
                derivation_index: 42,
                confirmation_time: None,
            }),
        }
    }

    fn get_test_utxos() -> Vec<WeightedUtxo> {
        vec![
            utxo(
                100_000,
                500_000,
                bitcoin::PublicKey::from_str(
                    "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
                )
                .expect("pubkey"),
                0,
                false,
            ),
            utxo(
                FEE_AMOUNT - 40,
                40_000,
                bitcoin::PublicKey::from_str(
                    "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
                )
                .expect("pubkey"),
                1,
                false,
            ),
            utxo(
                200_000,
                250_000,
                bitcoin::PublicKey::from_str(
                    "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
                )
                .expect("pubkey"),
                2,
                false,
            ),
        ]
    }

    #[test]
    fn test_largest_first_coin_selection_success() {
        let utxos = get_test_utxos();
        let drain_script = ScriptBuf::default();
        let target_amount = 600_000;

        let result = Lrc20LargestFirstCoinSelection
            .coin_select(
                utxos,
                vec![],
                target_amount,
                &drain_script,
                TokenPubkey::from_str(
                    "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
                )
                .expect("pubkey"),
            )
            .unwrap();

        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected_amount(), 790_000);
    }
}
