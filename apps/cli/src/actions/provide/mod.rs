use bitcoin::Txid;
use clap::Args;
use color_eyre::eyre::{self, Context as EyreContext, bail};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrc20_types::{Lrc20TxType, TransferProofs};
use lrcdk::bitcoin_provider::BitcoinProvider;
use lrcdk::txbuilder::form_issue_announcement;

use crate::actions::proof::ProofListArgs;
use crate::context::Context;

#[derive(Args, Debug)]
pub struct ProvideArgs {
    #[clap(flatten)]
    pub proofs: ProofListArgs,

    /// Transaction id.
    #[clap(long)]
    pub txid: Txid,

    /// Confirmations
    #[clap(long, default_value_t = 6)]
    pub confirmations: u32,
}

pub(crate) async fn run(
    ProvideArgs {
        proofs,
        txid,
        confirmations,
    }: ProvideArgs,
    mut context: Context,
) -> eyre::Result<()> {
    let bitcoin_provider = context.bitcoin_provider()?;

    let tx_confirmations = bitcoin_provider.get_tx_confirmations(&txid)?;

    if tx_confirmations < confirmations {
        bail!(
            "Transaction has {} confirmations, which is less than min: {}",
            tx_confirmations,
            confirmations
        );
    }

    let TransferProofs { input, output } = proofs.into_proof_maps()?;

    let tx_type = if input.is_empty() {
        let announcement = form_issue_announcement(output.clone().into_values().collect())?;

        Lrc20TxType::Issue {
            output_proofs: Some(output),
            announcement,
        }
    } else {
        Lrc20TxType::Transfer {
            input_proofs: input,
            output_proofs: output,
        }
    };

    let lrc20_client = context.lrc20_client()?;

    lrc20_client
        .provide_lrc20_proof_short(txid, tx_type.hex(), None)
        .await
        .wrap_err("Failed to provide rpoof to node")?;

    Ok(())
}
