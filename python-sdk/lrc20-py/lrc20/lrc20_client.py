import json
from typing import List
from uuid import uuid4

import requests

from .electrs.electrs import ElectrsClient
from .lrc20_types import BitcoinUtxo, Receipt, Lrc20Utxo, Lrc20UtxoType


class Lrc20Client:
    def __init__(self, rpc_url: str, electrs_client: ElectrsClient):
        """
        Initialize the Lrc20Client with the RPC URL and an instance of ElectrsClient.

        - `rpc_url` - The URL for the RPC server
        - `electrs_client` - An instance of ElectrsClient for interacting with the Bitcoin blockchain
        """
        self._rpc_url = rpc_url.rstrip("/")  # Remove trailing slash from the RPC URL
        self._electrs_client = electrs_client  # Store the ElectrsClient instance

    def send_lrc20_tx(self, raw_tx_hex: str) -> bool | None:
        """
        Send a LRC20 transaction in hex format.

        - `raw_tx_hex` - The hex-encoded LRC20 transaction to send

        Returns the result of the RPC call to send the transaction.
        """
        return self._rpc_request("sendlrc20transaction", {"lrc20_tx": raw_tx_hex})

    def get_lrc20_tx_status(self, txid: str) -> str:
        """
        Get the status of a LRC20 transaction.

        - `txid` - LRC20 transaction id

        Returns the result of the RPC call to get the transaction status.
        """
        tx_response = self._rpc_request("getlrc20transaction", {"txid": txid})
        if tx_response is None:
            return "none"

        return tx_response["status"]

    def emulate_lrc20_tx(self, raw_tx_json: str) -> bool | None:
        """
        Emulate a LRC20 transaction in json format.

        - `raw_tx_json` - The json-encoded LRC20 transaction to send

        Returns the result of the RPC call to emulate the transaction.
        """
        return self._rpc_request(
            "emulatelrc20transaction", {"lrc20_tx": json.loads(raw_tx_json)}
        )

    def list_lrc20_transactions(self, page: int) -> List[dict]:
        """
        List LRC20 transactions by page.

        - `page` - The page number to list transactions from

        Returns the result of the RPC call to list transactions.
        """
        response = self._rpc_request("listlrc20transactions", [page])

        if not response:
            return []

        return response

    def _rpc_request(self, method, params=None):
        """
        Perform an RPC request to the LRC20 server.

        - `method` - The RPC method to call
        - `params` - Optional parameters for the RPC method

        Returns the result of the RPC call if successful, or None if an error occurs.
        """
        if params is None:
            params = []  # Default to an empty list if no parameters are provided

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": str(uuid4()),  # Unique identifier for the request
        }

        try:
            response = requests.post(
                self._rpc_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()  # Raise an exception for HTTP errors
            response_json = response.json()

            if "error" in response_json:
                raise ValueError(
                    f"RPC Error: {response_json['error']}"
                )  # Raise an error if the RPC call failed

            return response_json.get("result")

        except requests.RequestException as e:
            print(f"HTTP Request failed: {e}")  # Print HTTP request error
            return None
        except ValueError as e:
            print(e)  # Print RPC error
            return None

    def _utxos(self, pubkey, utxos, tweaked_sats, starting_page, starting_tx):
        """
        Retrieve UTXOs from LRC20 transactions.

        - `pubkey` - The public key to filter UTXOs
        - `utxos` - List to append LRC20 UTXOs
        - `tweaked_sats` - List to append tweaked Bitcoin UTXOs
        - `starting_page` - The page number to start retrieving transactions
        - `starting_tx` - The transaction index on the starting page to begin processing

        Returns a tuple of (utxos, tweaked_sats, current_page, last_indexed_tx).
        """
        current_page = starting_page
        last_indexed_tx = 0

        while True:
            lrc20_txs = self._rpc_request(
                "listlrc20transactions", {"page": current_page}
            )

            if not lrc20_txs:
                current_page -= 1  # No more transactions, go to previous page
                break

            for tx_num, lrc20_tx in enumerate(lrc20_txs):
                last_indexed_tx = tx_num + 1

                if current_page == starting_page and tx_num < starting_tx:
                    continue  # Skip transactions before the starting index on the starting page

                tx_type = lrc20_tx["tx_type"]["type"]
                txid = lrc20_tx["bitcoin_tx"]["txid"]
                if tx_type != "Transfer" and tx_type != "Issue":
                    continue  # Only process "Transfer" and "Issue" transaction types

                output_proofs = lrc20_tx["tx_type"]["data"].get("output_proofs", {})
                if output_proofs:
                    for index, proof in enumerate(output_proofs.values()):
                        proof_type = proof["type"]
                        if (
                            proof_type != "Sig"
                            and proof_type != "EmptyReceipt"
                            and proof_type != "P2TR"
                        ):
                            continue  # Only process "Sig", "EmptyReceipt" and "P2TR" proof types

                        inner_key = proof["data"]["inner_key"]

                        xonly = pubkey
                        if proof_type == "P2TR":
                            xonly = pubkey[2:]

                        if inner_key != xonly:
                            continue  # Skip UTXOs that do not match the public key
                        if tx_type == "Issue":
                            index += 1  # Adjust index for "Issue" transactions
                        if self._electrs_client.is_spent(txid, index):
                            continue  # Skip UTXOs that have been spent

                        sats = lrc20_tx["bitcoin_tx"]["output"][index]["value"]
                        bitcoin_utxo = BitcoinUtxo(sats, txid, index)

                        if proof_type == "Sig":
                            receipt_data = proof["data"]["receipt"]
                            token_amount = receipt_data["token_amount"]["amount"]
                            token_pubkey = receipt_data["token_pubkey"]
                            receipt = Receipt(token_amount, token_pubkey, inner_key)
                            utxo = Lrc20Utxo(receipt, bitcoin_utxo, Lrc20UtxoType.Sig)
                            utxos.append(utxo)  # Add LRC20 UTXO to the list

                        if proof_type == "P2TR":
                            receipt_data = proof["data"]["receipt"]
                            token_amount = receipt_data["token_amount"]["amount"]
                            token_pubkey = receipt_data["token_pubkey"]
                            receipt = Receipt(token_amount, token_pubkey, inner_key)
                            utxo = Lrc20Utxo(receipt, bitcoin_utxo, Lrc20UtxoType.P2TR)
                            utxos.append(utxo)  # Add LRC20 UTXO to the list

                        if proof_type == "EmptyReceipt":
                            sats = lrc20_tx["bitcoin_tx"]["output"][index]["value"]
                            bitcoin_utxo = BitcoinUtxo(sats, txid, index)
                            tweaked_sats.append(
                                bitcoin_utxo
                            )  # Add tweaked Bitcoin UTXO to the list

            current_page += 1  # Move to the next page

        return utxos, tweaked_sats, current_page, last_indexed_tx

    def __str__(self):
        """
        Return a string representation of the Lrc20Client instance.
        """
        return f"Lrc20Client(rpc_url={self._rpc_url}, electrs_client={self._electrs_client})"
