use std::process::exit;

use clap::{ArgGroup, Args};
use lrc20_types::{Lrc20Transaction, Lrc20TxType};

#[derive(Args, Debug, Clone)]
#[clap(group(
    ArgGroup::new("decode")
        .required(true)
        .args(&["tx", "proofs"])
        .multiple(false),
))]
pub struct DecodeArgs {
    pub hex: String,

    #[clap(long, group = "decode")]
    pub tx: bool,

    #[clap(long, group = "decode")]
    pub proofs: bool,
}

pub(crate) async fn run(
    DecodeArgs { hex, tx, proofs }: DecodeArgs,
) -> Result<(), color_eyre::Report> {
    if tx {
        let Ok(lrc20_tx) = Lrc20Transaction::from_hex(hex) else {
            eprintln!("The hex value could not be parsed as a LRC20 transaction");
            exit(1);
        };
        println!("{}", serde_json::to_string_pretty(&lrc20_tx)?);
        return Ok(());
    }

    if proofs {
        let Ok(tx_type) = Lrc20TxType::from_hex(hex) else {
            eprintln!("The hex value could not be parsed as a LRC20 proof");
            exit(1);
        };
        println!("{}", serde_json::to_string_pretty(&tx_type)?);
        return Ok(());
    }

    Ok(())
}
