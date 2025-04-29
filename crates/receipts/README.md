# `lrc20-receipts`

Crate which provides base primitives of the LRC20 protocol, such as [`TokenPubkey`],
[`TokenAmount`], [`ReceiptKey`], [`ReceiptHash`], [`ReceiptPrivateKey`] and [`ReceiptProof`]
used for sending, spending and validating the transactions created using the LRC20
protocol.

The main structure is [`ReceiptProof`] which helds all required information for
validator side (LRC20 node) to check if the proof attached to some output of the
Bitcoin transaction is valid.

Currently, crate supports only `P2WPKH` and `P2WSH` addresses with only specific
subset for the last one. They are:

## `P2WPKH` proof

* [`SigReceiptProof`] - single signature proof for input/output.

## `P2WSH` proofs

* [`MultisigReceiptProof`] - input/output proof that has a multisignature redeem
  script with an arbitary number of participants.
* [`LightningCommitmentProof`] - input/ouput proof for Lightning commitment transaction [`to_local` output].
* [`LightningHtlcProof`] - input/output proof for Lightning commitment transaction [`htlc` output].

> In future, arbitary scripts that have public key in it will be supported.

## Example

Suppose Alice wants to send 5 LRC20 coins to Bob. For that, she needs to create a
[`ReceiptKey`] with 5 LRC20 coins and Bob's key as a spender:

```rust
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, Network};
use lrc20_receipts::{ReceiptKey, TokenPubkey, TokenAmount, Receipt};

// Get Bob's public key
let bob_pubkey = PublicKey::from_str(
    "020677b5829356bb5e0c0808478ac150a500ceab4894d09854b0f75fbe7b4162f8"
).unwrap();

// Create receipt with 5 as TokenAmount and some TokenPubkey
let token_pubkey = TokenPubkey::from_str(
    "026a5e3a83f0b2bdfb2f874c6f4679dc02568deb8987d11314a36bceacb569ad8e"
).unwrap();
let token_amount = TokenAmount::from(5);
let receipt = Receipt::new(token_amount, token_pubkey);

let receipt_key = ReceiptKey::new(receipt, &bob_pubkey).unwrap();

// Generate address for sending LRC20 coins (Regtest is used as an example).
let address = Address::p2wpkh(&receipt_key.into(), Network::Regtest).unwrap();

println!("{address}");
```

Where `receipt_key` is a public key with LRC20 coins in it. These coins can be spent
only by Bob. Then Alice can generate a P2WPKH address from `receipt_key` and add it
as an output of the Bitcoin transaction.

After that, Alice needs to create a proof for it, and send it to the LRC20 node for
validation:

```rust
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, Network};
use lrc20_receipts::{TokenPubkey, TokenAmount, Receipt, ReceiptProof};

// Get Bob's public key
let bob_pubkey = PublicKey::from_str(
    "020677b5829356bb5e0c0808478ac150a500ceab4894d09854b0f75fbe7b4162f8"
).unwrap();

// Create receipt with 5 as TokenAmount and some TokenPubkey
let token_pubkey = TokenPubkey::from_str(
    "026a5e3a83f0b2bdfb2f874c6f4679dc02568deb8987d11314a36bceacb569ad8e"
).unwrap();
let receipt = Receipt::new(5, token_pubkey);

// Create a single signature P2WPKH output
let proof = ReceiptProof::sig(receipt, bob_pubkey, None); 
```

[`to_local` output]: https://github.com/lightning/bolts/blob/8a64c6a1cef979b3f0cecb00ba7a48c2d28b3588/03-transactions.md#to_local-output
[`htlc` output]: https://github.com/lightning/bolts/blob/8a64c6a1cef979b3f0cecb00ba7a48c2d28b3588/03-transactions.md#offered-htlc-outputs
