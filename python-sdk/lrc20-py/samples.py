import asyncio
import lrcdk
import time

from lrc20.electrs.client.json_rpc import JsonRpcElectrsClient
from lrc20.lrc20_client import Lrc20Client
from lrc20.wallet import Wallet
from lrc20.lrc20_types import Payment
from lrc20.db import dbm

NETWORK = "testnet"

USD_PRIVKEY = "cPqC9nAwBtSqHshkvheh6qTsRh17XakB2vpZeMEso6pKniMswsSq"
"""
USD issuer private key we will use to issue (mint) LRC20 tokens.
"""
USD_PUBKEY = "035b30e4fbf542edfcd598995040c797e66e9e7f50b100616facdf53ffc1046030"
"""
USD issuer public key we will use to fetch LRC20 utxos to make a transfer.
"""
USD_XONLY_PUBKEY = USD_PUBKEY[2:]
"""
USD issuer X only public key we will use for LRC20 coin selection.
"""
ALICE_PUBKEY = "02b2eb79ee60f4755819f893c747b370096fa04c3b3b1fe7fb7bcdb35551dc3caf"
"""
ALICE public key that we will use as a recipient public key while transferring LRC20
tokens from USD to ALICE.
"""
ALICE_XONLY_PUBKEY = ALICE_PUBKEY[2:]
"""
Alice X only public key we will use for LRC20 coin selection.
"""
ELECTRS_CLI = JsonRpcElectrsClient("18.215.149.26", 30768)
"""
Electrs client that uses Electrs API for the following purposes:


- fetch Bitcoin UTXOs.
- get tx by id.
- check if a UTXO is spent.
"""

LRC20_CLI = Lrc20Client("https://rpc.lrc20d.mutiny.18.215.149.26.sslip.io", ELECTRS_CLI)
"""
LRC20 client we will use to fetch LRC20 UTXOs.
"""

FEE_RATE_VB = 2.0
DB_PATH = ".wallet_db.dev"


async def main():
    pesristent_storage = dbm.PersistentLrc20Storage(DB_PATH)
    wallet = Wallet(
        LRC20_CLI, lrcdk.PyPrivateKey(USD_PRIVKEY), pesristent_storage, NETWORK
    )

    print(f"P2WPKH: {wallet.p2wpkh_address()}")
    print(f"P2TR: {wallet.p2tr_address()}")

    await wallet.sync()
    print(f"LRC20 balances: {wallet.lrc20_balances()}")
    print(f"BTC balance: {wallet.btc_balance()}")

    tx = await issue(wallet)
    # tx = await transfer_p2tr(wallet)
    # tx = await transfer(wallet)
    # tx = await freeze(wallet)
    # tx = await token_pubkey_announcement(wallet)
    # tx = await transfer_ownership(wallet)

    txid = lrcdk.txid(tx)
    print(f"LRC20 tx hex: {lrcdk.encode_lrc20_tx(tx)}")
    print(f"LRC20 tx id: {lrcdk.txid(tx)}")

    try:
        response = wallet.broadcast_lrc20_tx(tx)
        print(f"Tx broadcast result: {response}")
    except Exception as e:
        print(e)

    tx_status = LRC20_CLI.get_lrc20_tx_status(txid)
    while tx_status != "attached":
        if tx_status == "none":
            print(f"LRC20 tx {txid} was rejected by the node")
            return

        print(f"LRC20 tx status: {tx_status}")
        time.sleep(3)
        tx_status = LRC20_CLI.get_lrc20_tx_status(txid)

    print(f"LRC20 tx {txid} is attached")


# Issue USD tokens to USD
async def issue(wallet):
    payment = Payment(USD_XONLY_PUBKEY, USD_PUBKEY, 11111, 1000)
    return await wallet.issue([payment], FEE_RATE_VB)


# Transfer USD tokens from USD to ALICE
async def transfer(wallet):
    paymentToUSD = Payment(USD_XONLY_PUBKEY, ALICE_PUBKEY, 8000, 1000)
    return await wallet.transfer([paymentToUSD], FEE_RATE_VB)


# Transfer USD tokens from USD to ALICE
async def transfer_p2tr(wallet):
    paymentToUSD = Payment(USD_XONLY_PUBKEY, ALICE_XONLY_PUBKEY, 11111, 1000, True)
    return await wallet.transfer([paymentToUSD], FEE_RATE_VB)


# Freeze an outpoint
async def freeze(wallet):
    return await wallet.freeze(
        USD_XONLY_PUBKEY,
        lrcdk.OutPoint(
            "7c5f5386e0b1fa4c31ac8a84a5d2ab28ebad3d7869ac85f538fda50a4b522228", 1
        ),
        FEE_RATE_VB,
    )


# Create a token_pubkey announcement
async def token_pubkey_announcement(wallet):
    return await wallet.token_pubkey_announcement(
        USD_XONLY_PUBKEY, "Test", "TST", 10, 0, False, FEE_RATE_VB
    )


# Transfer ownership of token_pubkey
async def transfer_ownership(wallet):
    return await wallet.transfer_ownership(
        USD_XONLY_PUBKEY, "0014841b80d2cc75f5345c482af96294d04fdd66b2b7", FEE_RATE_VB
    )


if __name__ == "__main__":
    asyncio.run(main())
