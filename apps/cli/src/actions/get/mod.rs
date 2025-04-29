use std::process::exit;

use bitcoin::Txid;
use clap::Args;
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

use crate::context::Context;

#[derive(Args, Debug, Clone)]
pub struct GetArgs {
    #[clap(long, short)]
    pub txid: Txid,

    /// Display only proofs of the LRC20 transaction if this flag is set.
    #[clap(long)]
    pub proofs: bool,
}

pub(crate) async fn run(
    GetArgs { txid, proofs }: GetArgs,
    mut context: Context,
) -> Result<(), color_eyre::Report> {
    let client = context.lrc20_client()?;

    let tx_reponse = client.get_lrc20_transaction(txid).await?;

    if proofs {
        let Some(lrc20_tx) = &tx_reponse.data else {
            eprintln!("Tx {} is not present in node's storage", txid);
            exit(1);
        };

        println!("{}", lrc20_tx.tx_type.hex());
    } else {
        println!("{}", serde_json::to_string_pretty(&tx_reponse)?);
    }

    Ok(())
}
