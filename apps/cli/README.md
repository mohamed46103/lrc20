# `lrc20-cli`

CLI tool for managing LRC20 transactions.

## Features

- Create a LRC20 transaction (`transfer`, `issue`, `freeze`):
    - Issue an asset from your pair of keys;
    - Transfer issued tokens;
    - Freeze, unfreeze LRC20 outputs;
    - Burn LRC20 tokens;
- Communicate with a LRC20 node (`node` subcommand):
    - Provide receipt proofs to the LRC20 node;
    - Get LRC20 transactions from the LRC20 node;
- Validate proofs locally (`validate` subcommand);
- Generate LRC20 addresses, key-pairs, receipt hashes (`generate` subcommand);
- Convert instances between each other (`convert` subcommand).

## Build and install

Clone git repository:

```sh
git clone git@github.com:lightsparkdev/lrc20.git
```

Install using  `cargo`:

> `bulletproof` feature is optional and required only for [step 7]

```sh
cargo install --path ./apps/cli --features bulletproof
```

From now, if you've added `$HOME/.cargo/bin` to your `$PATH`, `lrc20-cli`
should be available from your terminal session.

## Usage

Setup configuration file:

```toml
# config.toml
private_key = "cMzCipjMyeNdnPmG6FzB1GAL7ziTBPQ2TJ4EPWZWPdeGgbLTCAEE"

storage = "path/to/storage"

[bitcoin_provider]
type = "bitcoin_rpc"
url = "http://127.0.0.1:18443" # bitcoin node RPC url
network = "regtest"
auth = { username = "admin1", password = "123" }
# Start syncing the blockchain history from the certain timestamp
start_time = 0

# Or if you want to use Esplora:
# [bitcoint-provider]
# type = "esplora"
# url = "http://127.0.0.1:3000"
# network = "regtest"
# # stop gap - It is a setting that determines when to stop fetching transactions for a set of
# # addresses by indicating a gap of unused addresses. For example, if set to 20, the syncing
# # mechanism would stop if it encounters 20 consecutive unused addresses.
# stop_gap = 20


[lrc20_rpc]
url = "http://127.0.0.1:18333"

# The fee rate strategy. Possible values:
# - { type = "estimate", target_blocks: 2 } The fee rate is fetched from Bitcoin RPC. If an error
#   occurs, the tx building process is interrupted.
# - { type = "manual", fee_rate = 1.0 } Default fee rate is used.
# - { type = "try_estimate", fee_rate = 1.0, target_blocks: 2 } The fee rate is fetched
#   automatically from Bitcoin RPC. If an error occurs, the default fee rate is used.
# NOTE: fee_rate is measured in sat/vb.
# https://developer.bitcoin.org/reference/rpc/estimatesmartfee.html
[fee_rate_strategy]
type = "manual"
fee_rate = 1.2
```

### Simple scenario

Let's go through steps of usage scenario:

0. Setup local LRC20 and Bitcoin nodes localy;
1. Synchronize all the wallet history (see [step 1]);
2. Create **USD Issuer** and **EUR Issuer** accounts which will issue tokens to
   users (see [step 2]);
3. Generate two key pairs of keys that will transfer LRC20-coins between each other
   (let's name them **Alice** and **Bob**, see [step 3]);
4. Issue **USD** and **EUR** tokens to **Alice** (see [step 4]);
    - Check **Alice**'s balances and UTXO.
5. Transfer issued tokens from **Alice** to **Bob** (see [step 5]);
    - Perform a monotoken transfer.
    - Perform a multitoken transfer.
6. Using **USD Issuer**'s keys create a freeze transaction for **Bob**'s output
   (see [step 6]);
7. Using **USD Issuer**'s keys create an unfreeze transaction for **Bob**'s output (see [step 7]);
8. Burn LRC20 tokens (see [step 8]);
9. Bulletproof (see [step 9]);

#### 0. Setup LRC20 and Bitcoin nodes localy;

See [infrastructure README](/infrastructure/README.md).

#### 1. Synchronize the wallet history

Use the following command to synchronize your wallet:

> NOTE: replace the `config.toml` with a path to your configuration file.

```sh
lrc20-cli --config ./config.toml wallet sync
```

It could take some time, so be calm and make a cup of coffee for yourself. Also you can change
`start_time` field in the `[bitcoin_provider]` section to cut down on synchronizing time. If you
want to
interrupt the syncing process, use the following command:

```sh
lrc20-cli --config ./config.toml wallet abort-rescan
```

This command will be done in case when you are using `bitcoin_rpc` configuration for
`[bitcoin_provider]` (see  [usage]);

#### 2. Generate **USD Issuer** and **EUR Issuer** key pairs

Generate **EUR Issuer** key pair:

```sh
lrc20-cli generate keypair --network regtest
```

RESULT:

```text
Private key: cUK2ZdLQWWpKeFcrrD7BBjiUsEns9M3MFBTkmLTXyzs66TQN72eX
P2TR address: bcrt1phynjv46lc4vsgdyu8qzna4rkx0m6d2s48cjmx8mtcqkey5r23t2swjhv5n
P2WPKH address: bcrt1qplal8wyn20chw4jfdamkk5vnfkpwdm3vyd46ew
```

<details>
<summary>Configuration file for <b>EUR Issuer</b> </summary>

```toml
# eur.toml
private_key = "cUK2ZdLQWWpKeFcrrD7BBjiUsEns9M3MFBTkmLTXyzs66TQN72eX"

storage = ".users/eur"

[bitcoin_provider]
type = "bitcoin_rpc"
url = "http://127.0.0.1:18443"
auth = { username = "admin1", password = "123" }
network = "regtest"
start_time = 0

[lrc20_rpc]
url = "http://127.0.0.1:18333"

[fee_rate_strategy]
type = "manual"
fee_rate = 1.2
```

</details>

**USD Issuer** keypair:

```text
Private key: cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9
P2TR address: bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30
P2WPKH address: bcrt1qycd9xdayguzayn40ua56slsdm0a9ckn3n34tv0
```

<details>
<summary>Configuration file for <b>USD Issuer</b> </summary>

```toml
# usd.toml
private_key = "cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9"

storage = ".users/usd"

[bitcoin_provider]
type = "bitcoin_rpc"
url = "http://127.0.0.1:18443"
auth = { username = "admin1", password = "123" }
network = "regtest"
start_time = 0

[lrc20_rpc]
url = "http://127.0.0.1:18333"

[fee_rate_strategy]
type = "manual"
fee_rate = 1.2
```

</details>

#### 3. Generate **Alice** and **Bob** key pairs

Generate a key pair for **Alice**:

```text
Private key: cQb7JarJTBoeu6eLvyDnHYNr6Hz4AuAnELutxcY478ySZy2i29FA
P2TR address: bcrt1phhfvq20ysdh6ht8fhtp7e8xfemva23lr703mtyrnuv7fkdggayvsz8x8gd
P2WPKH address: bcrt1q69j54cjd44wuvaqv4lmnyrw89ve4ufq3cx37mr
```

<details>
<summary>Configuration file for <b>Alice</b></summary>

```toml
# alice.toml
private_key = "cQb7JarJTBoeu6eLvyDnHYNr6Hz4AuAnELutxcY478ySZy2i29FA"

storage = ".users/alice"

[bitcoin_provider]
type = "bitcoin_rpc"
url = "http://127.0.0.1:18443"
auth = { username = "admin1", password = "123" }
network = "regtest"
start_time = 0

[lrc20_rpc]
url = "http://127.0.0.1:18333"

[fee_rate_strategy]
type = "manual"
fee_rate = 1.2
```

</details>

and **Bob**:

```text
Private key: cUrMc62nnFeQuzXb26KPizCJQPp7449fsPsqn5NCHTwahSvqqRkV
P2TR address: bcrt1p03egc6nv2ardypk2qpwru20sv7pfsxrn43wv7ts785rq5s8a8tmqjhunh7
P2WPKH address: bcrt1q732vnwgml595glrucr00rt8584x58mjp6xtnmf
```

<details>
<summary>Configuration file for <b>Bob</b></summary>

```toml
# bob.toml
private_key = "cUrMc62nnFeQuzXb26KPizCJQPp7449fsPsqn5NCHTwahSvqqRkV"

storage = ".users/bob"

[bitcoin_provider]
type = "bitcoin_rpc"
url = "http://127.0.0.1:18443"
auth = { username = "admin1", password = "123" }
network = "regtest"
start_time = 0

[lrc20_rpc]
url = "http://127.0.0.1:18333"

[fee_rate_strategy]
type = "manual"
fee_rate = 1.2
```

</details>

Also, lets copy their keys to environmental variables:

```sh
# P2TR adresses with encoded token pubkey for LRC20 transfers
export ALICE="$(lrc20-cli -c alice.toml p2tr)"
export BOB="$(lrc20-cli -c bob.toml p2tr)"
export USD="$(lrc20-cli -c usd.toml p2tr)"
export EUR="$(lrc20-cli -c eur.toml p2tr)"
# P2WPKH addresses for funding with Bitcoins
export ALICEW="$(lrc20-cli -c alice.toml p2wpkh)"
export BOBW="$(lrc20-cli -c bob.toml p2wpkh)"
export USDW="$(lrc20-cli -c usd.toml p2wpkh)"
export EURW="$(lrc20-cli -c eur.toml p2wpkh)"
```

For interactions with the local Bitcoin node you would need `bitcoin-cli`, but
if you don't have one, you can create alias to use one from a Docker container:

```sh
alias bitcoin-cli="docker compose --file $(pwd)/infrastructure/dev/docker-compose.yaml --project-directory $(pwd) exec bitcoind bitcoin-cli"
```

Then, lets fund issuers with Bitcoins:

```sh
bitcoin-cli generatetoaddress 101 $USDW
bitcoin-cli generatetoaddress 101 $EURW
```

#### 4. Create issuances for **Alice**

Now we are ready to create issuance of 10000 **USD** tokens for **Alice**:

```sh
lrc20-cli --config ./usd.toml issue --amount 10000 --recipient $ALICE
```

Where `amount` is issuance amount, `recipient` - **Alice**'s public key (read
from environment variable added in [step 2]).

RESULT:

```text
tx id: b51cbc492b1ee31897defc0349aac93b4b13f1fbfb77a07d47e01fcd54f6e607
tx hex: 01000000000101838fec46940f7337004ad6bbe7cee6177b91ef29b327bdfbe12de8ff454a5f5e0000000000feffffff030000000000000000376a357975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000e8030000000000001600145510fe1d689b2f68c6a861c50dae500506d0220320dcf50500000000160014889b6e052cad94c93296132dfa637e77ef03f1e1024730440220741c112dd1285194497116fd693265db1d451e6547ed4ad302dcb744db8180ab02201675b5e957bfa1201cf239023bb783b7b112167a4a6a4b4c04e7b84b1e7e5746012103ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab266000000007975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000010200000001000000000000000000000000000000000000271000000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919020000000502ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2
```

As the result, you will get the transaction ID and hex. By parameters obtained from configuration file,
`lrc20-cli` will send it for broadcasting to LRC20 node with created proofs, where
the node will wait until the tranasction is mined to check it before accepting.

Using `bitcoin-cli` let's mine the next block:

```sh
bitcoin-cli generatetoaddress 6 $USDW
```

Check that the transaction has been accepted by the node:

```sh
lrc20-cli --config ./usd.toml get --txid b51cbc492b1ee31897defc0349aac93b4b13f1fbfb77a07d47e01fcd54f6e607
```

As a sign of acceptance, you would receive a LRC20 transaction in HEX format.

Also, we can check current **Alice**'s balances:

```sh
lrc20-cli --config ./alice.toml balances
```

RESULT:

```text
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 10000
```

To see the structure of the LRC20 transaction in JSON format, use the `decode` CLI command:

```sh
lrc20-cli decode --tx 01000000000101838fec46940f7337004ad6bbe7cee6177b91ef29b327bdfbe12de8ff454a5f5e0000000000feffffff030000000000000000376a357975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000e8030000000000001600145510fe1d689b2f68c6a861c50dae500506d0220320dcf50500000000160014889b6e052cad94c93296132dfa637e77ef03f1e1024730440220741c112dd1285194497116fd693265db1d451e6547ed4ad302dcb744db8180ab02201675b5e957bfa1201cf239023bb783b7b112167a4a6a4b4c04e7b84b1e7e5746012103ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab266000000007975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000010200000001000000000000000000000000000000000000271000000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919020000000502ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2
```

As the result, you will get the LRC20 transaction in human-readable format:

```json
{
  "bitcoin_tx": {
    "version": 1,
    "lock_time": 102,
    "input": [
      {
        "previous_output": "5e5f4a45ffe82de1fbbd27b329ef917b17e6cee7bbd64a0037730f9446ec8f83:0",
        "script_sig": "",
        "sequence": 4294967294,
        "witness": [
          "30440220741c112dd1285194497116fd693265db1d451e6547ed4ad302dcb744db8180ab02201675b5e957bfa1201cf239023bb783b7b112167a4a6a4b4c04e7b84b1e7e574601",
          "03ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
        ]
      }
    ],
    "output": [
      {
        "value": 0,
        "script_pubkey": "6a357975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000"
      },
      {
        "value": 1000,
        "script_pubkey": "00145510fe1d689b2f68c6a861c50dae500506d02203"
      },
      {
        "value": 99998752,
        "script_pubkey": "0014889b6e052cad94c93296132dfa637e77ef03f1e1"
      }
    ]
  },
  "tx_type": {
    "type": "Issue",
    "data": {
      "output_proofs": {
        "1": {
          "type": "Sig",
          "data": {
            "receipt": {
              "token_amount": {
                "amount": 10000
              },
              "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
            },
            "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
          }
        },
        "2": {
          "type": "EmptyReceipt",
          "data": {
            "inner_key": "02ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          }
        }
      },
      "announcement": {
        "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2",
        "amount": 10000
      }
    }
  }
}
```

> There is an empty receipt. It doesn't hold any Receipt data, it is
> just empty proof indicating that this Bitcoin output holds only satoshis
> and zero LRC20 tokens.

The `decode` method is also able to decode hex encoded LRC20 proofs, which can be obtained with the following command:

```sh
lrc20-cli --config ./usd.toml get --txid b51cbc492b1ee31897defc0349aac93b4b13f1fbfb77a07d47e01fcd54f6e607 --proofs
```

Result is as follows:

```text
007975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000010200000001000000000000000000000000000000000000271000000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919020000000502ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2
```

You can now decode it:

```sh
lrc20-cli decode --proofs 007975760002ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab210270000000000000000000000000000010200000001000000000000000000000000000000000000271000000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919020000000502ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2
```

The command will show you only the transaction type and LRC20 proofs, which is useful when you don't need to see the Bitcoin transaction data:

```json
{
  "type": "Issue",
  "data": {
    "output_proofs": {
      "1": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 10000
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      },
      "2": {
        "type": "EmptyReceipt",
        "data": {
          "inner_key": "02ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
        }
      }
    },
    "announcement": {
      "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2",
      "amount": 10000
    }
  }
}
```

Let's do the same with **EUR Issuer**:

```sh
lrc20-cli --config ./eur.toml issue --amount 10000 --recipient $ALICE
bitcoin-cli generatetoaddress 6 $USDW
```

And check balances again:

```sh
lrc20-cli --config ./alice.toml balances
```

RESULT:

```text
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 10000
bcrt1phynjv46lc4vsgdyu8qzna4rkx0m6d2s48cjmx8mtcqkey5r23t2swjhv5n: 10000
```

#### 5. Transfer from **Alice** to **Bob**

Now, let's move on to the transfer. Fund **Alice** with several Bitcoins:

```sh
bitcoin-cli generatetoaddress 101 $ALICEW
```

We are ready to transfer 1000 **USD** tokens from **Alice** to **Bob**:

```sh
lrc20-cli --config ./alice.toml transfer \
    --token_pubkey $USD \
    --amount 1000 \
    --recipient $BOB
```

RESULT:

```text
tx id: 493b87a94d12ba62bc4dbeb178056c769324b28c65a81c787e0a341a6a6e4ba0
tx hex: 010000000001021e3693ef6baab69a2363d61b5b7b2cec1423f2679537755b7763194383ec0fd40100000000feffffff07e6f654cd1fe0477da077fbfbf1134b3bc9aa4903fcde9718e31e2b49bc1cb50100000000feffffff03e80300000000000016001408fc812cf2568f414c1db93440380d0ccea5b6f5e8030000000000001600147bcd39708e5ea6e2dd72df1110c151bc30d66d84f7dbf5050000000016001430ccee4e57dfd7eca508ef46c015606d0469d53c02473044022001bdec0ea7e8ee543c3ba27acdba9cb6d493a2ee5e23bd64766a9ab5bd7c7b6b02206ce6dc427b9c0ab2d2696e6084883afc250400d5e2246b9588a08f16dad1f071012102bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e91902473044022065b934a8762e6f5d844070721e5b6ceb0d269d4c897749f46db5fdc84d5d4bba022015a9565b62a5fe66fcd3960462013c376f4d92cf6841cb0dd3e0f6595efbd18401210317c706e8ce08e46591040bc6e914e0a7b757401077fb2ca0422209859566a6ff6e000000010100000001000000000000000000000000000000000000271000000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919030000000000000000000000000000000000000000000003e800000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2027c728c6a6c5746d206ca005c3e29f06782981873ac5ccf2e1e3d060a40fd3af601000000000000000000000000000000000000232800000000000000000000000000000000ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab202bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919020000000502bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919
```

After decoding the transaction, you can see its structure:

```json
{
  "bitcoin_tx": {
    "version": 1,
    "lock_time": 110,
    "input": [
      {
        "previous_output": "d40fec83431963775b75379567f22314ec2c7b5b1bd663239ab6aa6bef93361e:1",
        "script_sig": "",
        "sequence": 4294967294,
        "witness": [
          "3044022001bdec0ea7e8ee543c3ba27acdba9cb6d493a2ee5e23bd64766a9ab5bd7c7b6b02206ce6dc427b9c0ab2d2696e6084883afc250400d5e2246b9588a08f16dad1f07101",
          "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        ]
      },
      {
        "previous_output": "b51cbc492b1ee31897defc0349aac93b4b13f1fbfb77a07d47e01fcd54f6e607:1",
        "script_sig": "",
        "sequence": 4294967294,
        "witness": [
          "3044022065b934a8762e6f5d844070721e5b6ceb0d269d4c897749f46db5fdc84d5d4bba022015a9565b62a5fe66fcd3960462013c376f4d92cf6841cb0dd3e0f6595efbd18401",
          "0317c706e8ce08e46591040bc6e914e0a7b757401077fb2ca0422209859566a6ff"
        ]
      }
    ],
    "output": [
      {
        "value": 1000,
        "script_pubkey": "001408fc812cf2568f414c1db93440380d0ccea5b6f5"
      },
      {
        "value": 1000,
        "script_pubkey": "00147bcd39708e5ea6e2dd72df1110c151bc30d66d84"
      },
      {
        "value": 99998711,
        "script_pubkey": "001430ccee4e57dfd7eca508ef46c015606d0469d53c"
      }
    ]
  },
  "tx_type": {
    "type": "Transfer",
    "data": {
      "input_proofs": {
        "1": {
          "type": "Sig",
          "data": {
            "receipt": {
              "token_amount": {
                "amount": 10000
              },
              "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
            },
            "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
          }
        }
      },
      "output_proofs": {
        "0": {
          "type": "Sig",
          "data": {
            "receipt": {
              "token_amount": {
                "amount": 1000
              },
              "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
            },
            "inner_key": "027c728c6a6c5746d206ca005c3e29f06782981873ac5ccf2e1e3d060a40fd3af6"
          }
        },
        "1": {
          "type": "Sig",
          "data": {
            "receipt": {
              "token_amount": {
                "amount": 9000
              },
              "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
            },
            "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
          }
        },
        "2": {
          "type": "EmptyReceipt",
          "data": {
            "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
          }
        }
      }
    }
  }
}
```

Generate several blocks using `bitcoin-cli`:

```sh
bitcoin-cli generatetoaddress 6 $USDW
```

And check balances of both users:

```sh
lrc20-cli --config ./alice.toml balances
```

RESULT:

```text
bcrt1phynjv46lc4vsgdyu8qzna4rkx0m6d2s48cjmx8mtcqkey5r23t2swjhv5n: 10000
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 9000
```

```sh
lrc20-cli --config ./bob.toml balances
```

RESULT:

```text
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 1000
```

##### Tweaked Bitcoin UTXOs and Sweep

You have already seen that LRC20 puts empty receipt proofs to the outputs that don't hold any LRC20
tokens.
These outputs are actually tweaked just like the outputs that hold actual Receipt data, but they are
tweaked
with empty receipts, i.e. with zero TokenAmount and TokenPubkey.

To spend these tweaked UTXOs, you need to create a **sweep** transaction. This means to create a
transaction which spends
all LRC20 outputs tweaked by zero receipts to a **P2WPKH address**.

This can be easily done with `lrc20-cli`.
In the above example, Alice's transfer transaction contained a change output that was tweaked with
an empty receipt.
To sweep it and all the other tweaked outputs (if any), Alice simply needs to execute:

```sh
lrc20-cli --config ./alice.toml sweep
```

RESULT:

```text
tx id: f552b5b5146b390c5c73e4a4f22920a5fff14e56dffe17ca7f8b3235324f6c06
```

If there are no tweaked Bitcoin outputs with empty Receipt proofs, the following message will be
displayed:

```text
Address has no tweaked Bitcoin UTXOs
```

##### Multitoken transfers

We covered monotoken transfers above (i.e. each transfer contained a single token-pubkey).
Now, let's try to perform a multitoken transfer and send both **EUR** and **USD** from **Alice**
to **Bob** in a single transfer.

As Alice's balance is already filled with some **EUR** and **USD**, we are ready to make a transfer:

```sh
lrc20-cli --config ./alice.toml transfer \
    --token_pubkey $USD \
    --amount 500 \
    --recipient $BOB \
    --token_pubkey $EUR \
    --amount 1000 \
    --recipient $BOB
```

Decoded proofs:

```json
{
  "type": "Transfer",
  "data": {
    "input_proofs": {
      "1": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 9000
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      },
      "2": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 10000
            },
            "token_pubkey": "b92726575fc55904349c38053ed47633f7a6aa153e25b31f6bc02d92506a8ad5"
          },
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      }
    },
    "output_proofs": {
      "0": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 500
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "027c728c6a6c5746d206ca005c3e29f06782981873ac5ccf2e1e3d060a40fd3af6"
        }
      },
      "1": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 1000
            },
            "token_pubkey": "b92726575fc55904349c38053ed47633f7a6aa153e25b31f6bc02d92506a8ad5"
          },
          "inner_key": "027c728c6a6c5746d206ca005c3e29f06782981873ac5ccf2e1e3d060a40fd3af6"
        }
      },
      "2": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 8500
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      },
      "3": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 9000
            },
            "token_pubkey": "b92726575fc55904349c38053ed47633f7a6aa153e25b31f6bc02d92506a8ad5"
          },
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      },
      "4": {
        "type": "EmptyReceipt",
        "data": {
          "inner_key": "02bdd2c029e4836fabace9bac3ec9cc9ced9d547e3f3e3b59073e33c9b3508e919"
        }
      }
    }
  }
}
```

Generate several blocks using `bitcoin-cli`:

```sh
bitcoin-cli generatetoaddress 6 $USDW
```

And check balances of both users:

```sh
lrc20-cli --config ./alice.toml balances
```

RESULT:

```text
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 8500
bcrt1phynjv46lc4vsgdyu8qzna4rkx0m6d2s48cjmx8mtcqkey5r23t2swjhv5n: 9000
```

```sh
lrc20-cli --config ./bob.toml balances
```

RESULT:

```text
bcrt1phynjv46lc4vsgdyu8qzna4rkx0m6d2s48cjmx8mtcqkey5r23t2swjhv5n: 1000
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 1500
```

**NOTE:** it's also acceptable to specify different recipients in a multitoken transfer.

#### 6. Freeze Bob's output

Let's see **Bob**'s LRC20 UTXOS:

```sh
lrc20-cli --config ./bob.toml utxos --token-pubkey $USD
```

RESULT:

```text
477df4cb007a46fe9efd7de75ffa7012846d9babea3f31bbb50c9b93f12ff7f5:0 1000
6936880d51e5fd92b6dd3c754905b538f146f69942080c4f3dca8b99d5f1f086:0 500
```

Using **USD Issuer**'s keys create a freeze transaction for **Bob**'s output:

```sh
lrc20-cli --config ./usd.toml freeze-toggle 477df4cb007a46fe9efd7de75ffa7012846d9babea3f31bbb50c9b93f12ff7f5 0
```

RESULT:

```text
Transaction broadcasted: abf54fedcdd13158b425f2841587f6874c5cc25935c3f2bd0b863ab7bac8e854
```

Generate several blocks using `bitcoin-cli`:

```text
bitcoin-cli generatetoaddress 6 $USDW
```

> Also, you can check if that transaction was indexed by node:

```sh
lrc20-cli --config ./usd.toml get --txid abf54fedcdd13158b425f2841587f6874c5cc25935c3f2bd0b863ab7bac8e854
```

And check **Bob**s UTXOS after that:

```sh
lrc20-cli --config ./bob.toml utxos --token-pubkey $USD
```

Now **Bob** has one less UTXO:

```text
6936880d51e5fd92b6dd3c754905b538f146f69942080c4f3dca8b99d5f1f086:0 500
```

#### 7. Unfreeze Bob's output

Using **Issuer**'s keys create an unfreeze transaction for **Bob**'s output:

```sh
lrc20-cli --config ./usd.toml freeze-toggle 477df4cb007a46fe9efd7de75ffa7012846d9babea3f31bbb50c9b93f12ff7f5 0
```

RESULT:

```text
Transaction broadcasted: 5faeae04cd7b4d853866eb427896a3a6fff89f2e2f320def1950cd30e0c43b8f
```

Generate block:

```sh
nigiri rpc --generate 1
```

Also, you may check if that transaction was indexed by node:

```sh
lrc20-cli --config ./usd.toml get --txid 5faeae04cd7b4d853866eb427896a3a6fff89f2e2f320def1950cd30e0c43b8f
```

And finally, check **Bob**'s LRC20 UTXOS:

```sh
lrc20-cli --config ./bob.toml utxos $USD
```

RESULT:

```text
477df4cb007a46fe9efd7de75ffa7012846d9babea3f31bbb50c9b93f12ff7f5:0 1000
6936880d51e5fd92b6dd3c754905b538f146f69942080c4f3dca8b99d5f1f086:0 500
```

#### 8. Burn LRC20 tokens

Let's suppose USD has the following balances:

```text
LRC20 balances:
bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30: 8000
```

Using the `burn` command create a burn transaction of 5000 tokens:

```sh
lrc20-cli --config ./usd.toml burn --amount 5000 --token-pubkey $USD
```

Decoded proofs:

```json
{
  "type": "Transfer",
  "data": {
    "input_proofs": {
      "1": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 8000
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "02ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
        }
      }
    },
    "output_proofs": {
      "0": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 5000
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "020202020202020202020202020202020202020202020202020202020202020202"
        }
      },
      "1": {
        "type": "Sig",
        "data": {
          "receipt": {
            "token_amount": {
              "amount": 3000
            },
            "token_pubkey": "ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
          },
          "inner_key": "03ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
        }
      },
      "2": {
        "type": "EmptyReceipt",
        "data": {
          "inner_key": "02ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2"
        }
      }
    }
  }
}
```

After the transaction is attached, the burnt tokens are impossible to spend.

It's easy to see that the recipient's public key is `020202020202020202020202020202020202020202020202020202020202020202`, which is actually an empty `TokenPubkey` that is used for empty receipts as well. LRC20 node tracks proofs with this inner key and doesn't allow spending these tokens, even though the probability to obtain the private key corresponding to this public key is miserably low.

#### 9. Bulletproofs

> **_NOTE:_** Change the build command in the [./infrastructure/build/lrc20d.dockerfile](../../infrastructure/build/lrc20d.Dockerfile)
> file to `cargo build --release -p lrc20d --features bulletproof`

> **_NOTE:_** Change the build command in the [./infrastructure/build/lrc20d.dockerfile](../../infrastructure/build/lrc20d.Dockerfile)
> file to `cargo build --release -p lrc20d --features bulletproof`

Bulletproof transactions are meant to be used to send anonymous transactions, i.e. transactions with hidden amounts.

> **_NOTE:_** TokenPubkeys and recipients are still visible to everyone. Only amounts are hidden.

Only those tokens that were issued using bulletproofs can be transfered anonymously.

Let's start with the bulletproof issuance of 10000 **USD** tokens for **Alice**:

```sh
lrc20-cli --config ./usd.toml bulletproof issue --satoshis 10000 --amount 10000 --recipient $ALICE
```

Result:

```text
a6c562fd8f1f4f42cc828b298def043af43f4ca95081f96f91bd8ae0cf6923c7
```

Copy the obtained result to the environment variable
```sh
export ISSUANCE_TX_ID="a6c562fd8f1f4f42cc828b298def043af43f4ca95081f96f91bd8ae0cf6923c7"
```

Generate several blocks using `bitcoin-cli`:

```text
a6c562fd8f1f4f42cc828b298def043af43f4ca95081f96f91bd8ae0cf6923c7
```

Copy the obtained result to the environment variable
```sh
export ISSUANCE_TX_ID="a6c562fd8f1f4f42cc828b298def043af43f4ca95081f96f91bd8ae0cf6923c7"
```

Generate several blocks using `bitcoin-cli`:

```sh
bitcoin-cli generatetoaddress 6 $USDW
```

Let's check that Pedersen's commitment to the issuance bulletproof that we received is valid:

```sh
lrc20-cli --config ./alice.toml bulletproof check --amount 10000 --outpoint $ISSUANCE_TX_ID:0 --sender $USD
```

Now, let's transfer 1000 **USD** tokens from **Alice** to **Bob**.
For that, we are passing the outpoint of the issuance we sent earlier:

```sh
export TRANSFER_TX_ID=$(lrc20-cli --config alice.dev.toml bulletproof transfer --amount 1000 --residual 9000 --satoshis 2000 --residual-satoshis 7000 --token-pubkey $USD --recipient $BOB --outpoint $ISSUANCE_TX_ID:0)
```

> **_NOTE:_** if you intend to send the transfer without change, just set `residual` and `residual-satoshis` to `0`.

Generate several blocks using `bitcoin-cli`:

```sh
bitcoin-cli generatetoaddress 6 $USDW
```

Finally check that Pedersen's commitment to the transfer bulletproof that we received is valid:

```sh
lrc20-cli --config ./bob.toml bulletproof check --amount 1000 --tx $TRANSFER_TX_ID:0 --sender $ALICE
```

> **_NOTE:_** multitoken bulletproof transfers are supported too.

[step 1]: #1-synchronize-the-wallet-history

[step 2]: #2-generate-usd-issuer-and-eur-issuer-key-pairs

[step 3]: #3-generate-alice-and-bob-key-pairs

[step 4]: #4-create-issuances-for-alice

[step 5]: #5-transfer-from-alice-to-bob

[step 6]: #6-freeze-bobs-output

[step 7]: #7-unfreeze-bobs-output

[step 8]: #8-burn-lrc20-tokens

[step 9]: #9-bulletproofs

[usage]: #usage

#### 9. TokenPubkey announcement

Any issuer can announce a new TokenPubkey (new token) to the network. This is done by creating a
transaction with a single output that contains `OP_RETURN` with information about the new TokenPubkey.

The next data is contained in the TokenPubkey announcement:

- `token-pubkey` - 32 bytes [`TokenPubkey`].
- `name` - 1 + [3 - 32] bytes name of the token. Where the first byte is the length of the name.
- `symbol` - 1 + [3 - 16] bytes symbol of the token. Where the first byte is the length of the
  symbol.
- `decimal` - 1 byte number of decimal places for the token.
- `max_supply` - 8 bytes maximum supply of the token.
- `is_freezable` - 1 byte indicates whether the token can be freezed or not by the issuer.

To announce a new TokenPubkey with `lrc20-cli` you need to execute the following command:

```sh
lrc20-cli --config ./usd.toml token-pubkey announcement --name "Some name" --symbol SMN --decimal 2
```

`token pubkey` isn't specified, so it was taken from the config. In this case the `max_supply` is 0 -
unlimited. `is_freezable` is set to `true` by default.

As a result, you will get the transaction ID of the TokenPubkey announcement transaction.

To check the TokenPubkey announcement, you can use the following command:

```sh
lrc20-cli --config ./alice.toml token-pubkey info --token-pubkey $USD
```

Result:

```text
TokenPubkey: bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30
Name: Some name
Symbol: SMN
Decimal: 2
Max supply: unlimited
Is freezable: true
```
