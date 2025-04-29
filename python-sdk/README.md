# LRC20 SDK

LRC20 SDK to build and sign LRC20 transactions. The bindings are created with [maturin](https://github.com/PyO3/maturin)

## How to create bindings

The SDK uses Rust bindings that can be found under [crates](crates).

To install the bindings, follow these steps:

1. Make sure maturin is installed. Then execute

```sh
maturin build -m ../crates/bindings-kit/Cargo.toml          
```

2. Then look for the wheels under `target/wheels/` and install them with the `pip` package installer

```sh
pip3 install target/wheels/lrcdk-0.4.3-cp38-abi3-macosx_11_0_arm64.whl           
```

> Note the wheel name can vary depending on the system.

## Examples

See examples in [samples.py](lrc20-py/samples.py).

### Initialize the wallet

First make sure to import all the required types:

```python
import asyncio
import lrcdk

from lrc20.esplora import EsploraClient
from lrc20.lrc20_client import Lrc20Client
from lrc20.wallet import Wallet
from lrc20.lrc20_types import Payment
from lrc20.db import dbm, in_memory

from bitcoinlib.keys import Key
```

Then initialize the Esplora client and LRC20 RPC client using the desired hosts:

```python
ESPLORA_CLI = EsploraClient("http://127.0.0.1:3000")
LRC20_CLI = Lrc20Client("http://127.0.0.1:18333", ESPLORA_CLI)
```

Data required to initialize the wallet and build transactions:

```python
NETWORK = 'regtest' # can provide any type, e.g. bitcoin, testnet, signet...
FEE_RATE_VB = 2.0
DB_PATH = ".wallet_db.dev" # Needed only if using a persistent storage

USD_PRIVKEY = "cVm5SC4zJYMbz8jHpZkTGQXxbwtyhX76dKb8HVKLnmxS6bbpxVjD"
USD_PUBKEY = "02a1f1ad0fe384b05504f8233209bad9e396f3f86b591e877dc1f95394306d9b94"
USD_XONLY_PUBKEY = USD_PUBKEY[2:]
ALICE_PUBKEY = "02b2eb79ee60f4755819f893c747b370096fa04c3b3b1fe7fb7bcdb35551dc3caf"
```

> X only public key is used to represent a TokenPubkey. More about x only public keys at [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

Next create a database. To save LRC20 utxos the wallet depends on the `Lrc20Database` interface, which currently has two implementations:
- `PersistentLrc20Storage` - utilezes `dbm` to store data
- `InMemoryLrc20Storage` - respectively, stores data in memory

To init an in-memory storage, simply do:

```python
storage = in_memory.InMemoryLrc20Storage()
```

And, to init a persistent storage, do the following:

```python
storage = dbm.PersistentLrc20Storage(DB_PATH)
```

Then initialize the wallet using the LRC20 RPC client, WIF, network and previosly created storage:

```python
wallet = Wallet(LRC20_CLI, Key.from_wif(USD_PRIVKEY), storage, NETWORK)
```

### Sync the wallet

To start using the wallet and fetch LRC20 utxos, it is required to sync it:

```python
await wallet.sync()
```

The sync operation removes spent utxos from the db and indexes new receipt proofs and writes them to the local utxo set.

> It is recommended to sync the wallet before each transaction.

### Build an issuance

To build an issuance, we need to create a `Payment`, which contains the token pubkey to send (basically, an X only public key), recipient's public key, LRC20 amount and Bitcoin amount in satoshis:

```python
payment = Payment(USD_XONLY_PUBKEY, USD_PUBKEY, 11111, 1000)

tx = await wallet.issue([payment], FEE_RATE_VB)
```

> NOTE: It's possible to provide more than one payment.

Also you can spend tweaked Bitcoin outputs, e.g. empty receipts, by setting the corresponding flag to `True`:

```python
tx = await wallet.issue([payment], FEE_RATE_VB, True)
```

### Transfer

The approach is the same as with the issuance:

```python
paymentToUSD = Payment(USD_XONLY_PUBKEY, ALICE_PUBKEY, 10000, 1000)
paymentToAlice = Payment(USD_XONLY_PUBKEY, USD_PUBKEY, 10000, 1000)
tx = await wallet.transfer([paymentToUSD, paymentToAlice], FEE_RATE_VB)
```

The only difference is that the transaction builder automatically adds LRC20 inputs to satisfy the conservartion rules.

### Announcements

The SDK supports all the types of announcements:
- Freeze announcement
- TokenPubkey announcement
- Transfer ownership announcement

#### Freeze announcement

To build a freeze announcement, call the `freeze` method with the desired TokenPubkey and an Outpoint (a combination of txid and index).

```python
tx = await wallet.freeze(USD_XONLY_PUBKEY, lrcdk.OutPoint("9153d543acff0c662d05664ac03a5381d5fb43b4ab0ac064b2dd456a38d41f33", 1))
```

#### TokenPubkey announcement

To build a token_pubkey announcement, call the `token_pubkey_announcement` method with the given parameters:
- TokenPubkey's x only public key
- Token's name
- Token's symbol
- The decimals of the token
- Max supply of the token
- A boolean value indicating if oupoints with this token pubkey can be frozen

```python
tx = await wallet.token_pubkey_announcement(USD_XONLY_PUBKEY, "Test", "TST", 10, 100000, False)
```

#### Transfer ownership announcement

To build a transfer ownership announcement, call the `transfer_ownership` method with the desired TokenPubkey and scriptPubKey hex of the new owner.

```python
tx = await wallet.transfer_ownership(USD_XONLY_PUBKEY, "0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
```

### Broadcast a transaction

Any LRC20 tx can be broadcasted using the LRC20 RPC client, but it should be hex encoded:

```python
tx_hex = lrcdk.lrc20_tx_hex(tx)
response = LRC20_CLI.send_lrc20_tx(tx_hex)
print(response) 
```

### Encoding and decoding

To encode and decode a LRC20 tx there are the following `lrcdk` functions:

```python
encoded_tx = lrcdk.encode_lrc20_tx(tx)
decoded_tx = lrcdk.decode_lrc20_tx(encoded_tx)

lrc20_tx_json = lrcdk.lrc20_tx_json(tx)
bitcoin_tx_hex = lrcdk.bitcoin_tx_hex(tx)

txid = lrcdk.txid(tx)
```
