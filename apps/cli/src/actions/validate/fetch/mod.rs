use std::sync::Arc;

use bdk::blockchain::GetTx;
use bitcoin::Txid;
use clap::Args;
use color_eyre::eyre::{self, bail};
use jsonrpsee::tracing::debug;
use lrc20_tx_check::check_transaction;
use lrc20_types::{Lrc20Transaction, Lrc20TxType, ProofMap, TransferProofs};
use lrcdk::txbuilder::form_issue_announcement;

use crate::context::Context;

use super::ProofListArgs;

#[derive(Args, Debug)]
pub struct CheckFetchArgs {
    /// Transaction hash.
    #[clap(long, short)]
    pub txid: Txid,
}

pub(crate) async fn run(
    proofs: ProofListArgs,
    CheckFetchArgs { txid }: CheckFetchArgs,
    mut context: Context,
) -> eyre::Result<()> {
    let blockchain = context.blockchain()?;

    let TransferProofs {
        input: input_proofs_map,
        output: output_proofs_map,
    } = proofs.into_proof_maps()?;

    debug!("Input proofs: {:?}", input_proofs_map);
    debug!("Output proofs: {:?}", output_proofs_map);

    check_p2wpkh_tx_by_id(blockchain, &txid, input_proofs_map, output_proofs_map).await?;

    println!("Transaction is valid!");

    Ok(())
}

pub async fn check_p2wpkh_tx_by_id(
    bitcoin_provider: Arc<bdk::blockchain::AnyBlockchain>,
    tx_id: &Txid,
    inputs: ProofMap,
    outputs: ProofMap,
) -> eyre::Result<()> {
    // Check that transaction exists at all
    let Some(tx) = bitcoin_provider.get_tx(tx_id)? else {
        bail!("Transaction not found : {}", tx_id);
    };

    let lrc20_tx_type = match inputs.is_empty() {
        true => Lrc20TxType::Issue {
            output_proofs: Some(outputs.clone()),
            announcement: form_issue_announcement(outputs.into_values().collect())?,
        },
        false => Lrc20TxType::Transfer {
            input_proofs: inputs,
            output_proofs: outputs,
        },
    };

    check_transaction(&Lrc20Transaction {
        bitcoin_tx: tx,
        tx_type: lrc20_tx_type,
    })?;

    Ok(())
}
