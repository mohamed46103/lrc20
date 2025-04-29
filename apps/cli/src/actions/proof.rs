use std::{collections::BTreeMap, str::FromStr};

use clap::Args;
use color_eyre::eyre::{self, bail};
use lrc20_receipts::{Receipt, ReceiptProof};
use lrc20_types::TransferProofs;

use super::types::LRC20Pubkey;

#[derive(Debug, Args)]
pub struct ProofListArgs {
    /// TokenPubkey of the receipt.
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: LRC20Pubkey,

    /// Number of the input in transaction.
    #[clap(long, num_args = 0..)]
    pub vin: Vec<u32>,

    /// Number of the output in transaction.
    #[clap(long, num_args = 1..)]
    pub vout: Vec<u32>,

    /// Recipient public key
    #[clap(long, num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub inner_key: Vec<LRC20Pubkey>,

    /// Amount of the token
    #[clap(long, num_args = 1..)]
    pub amount: Vec<u128>,
}

impl ProofListArgs {
    pub(crate) fn into_proof_maps(self) -> eyre::Result<TransferProofs> {
        let inputs_number = self.vin.len();
        let outputs_number = self.vout.len();

        let sum = inputs_number + outputs_number;
        if sum != self.inner_key.len() || sum != self.amount.len() {
            bail!("Number of inputs and outputs should be equal to number of keys and amounts");
        }

        // Take first N recipients and amount for inputs, where N is number of inputs.
        let inputs = self
            .inner_key
            .iter()
            .zip(self.amount.iter())
            .take(inputs_number)
            .zip(self.vin);
        // Take next M recipients and amount for outputs, where M is number of outputs.
        let outputs = self
            .inner_key
            .iter()
            .zip(self.amount.iter())
            .skip(inputs_number)
            .take(outputs_number)
            .zip(self.vout);

        // Convert inputs and outputs into [`ReceiptProof`]s
        let inputs = inputs
            .map(|((recipient, amount), vin)| {
                let receipt = Receipt::new(*amount, self.token_pubkey);
                (vin, ReceiptProof::sig(receipt, recipient.into(), None))
            })
            .collect::<BTreeMap<_, _>>();

        let outputs = outputs
            .map(|((recipient, amount), vout)| {
                let receipt = Receipt::new(*amount, self.token_pubkey);

                (vout, ReceiptProof::sig(receipt, recipient.into(), None))
            })
            .collect::<BTreeMap<_, _>>();

        Ok(TransferProofs {
            input: inputs,
            output: outputs,
        })
    }
}
