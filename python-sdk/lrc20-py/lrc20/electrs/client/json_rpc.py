import binascii
import hashlib
import json
import socket
from lrcdk import PyLrc20Transaction as Transaction
from ...lrc20_types import BitcoinUtxo
from ..electrs import ElectrsClient, DEFAULT_FEE
from ...utils import address_to_scripthash


class JsonRpcElectrsClient(ElectrsClient):
    def __init__(self, host: str, port: int):
        """
        Initialize the JsonRpcElectrsClient with the host, port, and optional headers.

        - `host` - Hostname for the Electrs JSON RPC API
        - `port` - Port number for the Electrs JSON RPC API
        - `headers` - Optional headers to include in requests (not used in socket communication)
        """
        self._host = host
        self._port = port
        self._request_id = 0

    def utxos(self, address: str) -> list[BitcoinUtxo]:
        """
        Retrieve UTXOs for a given Bitcoin address.

        - `address` - Bitcoin address to query

        Returns a list of BitcoinUtxo objects representing the UTXOs for the address, or None if an error occurs.
        """
        scripthash = address_to_scripthash(address)
        if scripthash is None:
            return None
        result = self._get_utxos_by_scripthash(scripthash)
        if result is None:
            return None

        utxos = []

        for utxo in result:
            utxo_obj = BitcoinUtxo(utxo["value"], utxo["tx_hash"], utxo["tx_pos"])
            utxos.append(utxo_obj)

        return utxos

    def get_tx(self, txid: str) -> Transaction:
        """
        Retrieve and parse a transaction by its ID.

        - `txid` - Transaction ID to query

        Returns a PyLrc20Transaction object representing the transaction, or None if an error occurs.
        """
        raw_tx = self.get_raw_tx(txid)
        if raw_tx is None:
            return None

        return Transaction.decode_lrc20_tx(raw_tx)

    def get_raw_tx(self, txid: str) -> str:
        """
        Retrieve the raw transaction hex by its ID.

        - `txid` - Transaction ID to query

        Returns the raw transaction hex as a string, or None if an error occurs.
        """
        return self._socket_request("blockchain.transaction.get", [txid])

    def get_fee(self, target: int) -> float:
        """
        Retrieve the fee estimate for a given confirmation target.

        - `target` - Confirmation target in blocks (1-25, 144, 504, 1008)

        Returns the estimated fee for the target, or DEFAULT_FEE if the estimate is not available.
        """
        result = self._socket_request("blockchain.estimatefee", [target])
        if result is None or result < 0:
            return DEFAULT_FEE
        return result

    def is_spent(self, txid: str, vout: int) -> bool:
        """
        Check if a specific output from a transaction has been spent.

        - `txid` - Transaction ID to query
        - `vout` - Output index to check

        Returns True if the output has been spent, False otherwise, or None if an error occurs.
        """
        try:
            tx = self.get_tx(txid)
        except Exception as e:
            print(f"Error retrieving transaction: {e}")
            return True

        if vout >= len(tx.outputs):
            return True

        output = tx.outputs[vout]
        script_pub_key = output.script.raw.hex()

        sha256_hash = hashlib.sha256(binascii.unhexlify(script_pub_key)).digest()
        scripthash = sha256_hash[::-1].hex()

        unspent_outputs = self._get_utxos_by_scripthash(scripthash)
        if unspent_outputs is None:
            return True

        for utxo in unspent_outputs:
            if utxo.get("tx_hash") == txid and utxo.get("tx_pos") == vout:
                return False

        return True

    def send_raw_tx(self, raw_tx_hex: str) -> str | None:
        """
        Send raw Bitcoin transaction.

        - `raw_tx_hex` - Hex encoded BTC transaction

        Returns the txid if the transaction is broadcasted successfully.
        """
        return self._socket_request("blockchain.transaction.broadcast", [raw_tx_hex])

    def _socket_request(self, method, params):
        """
        Perform a JSON-RPC request over a socket connection.

        - `method` - RPC method to call
        - `params` - Parameters for the RPC method

        Returns the result of the RPC call, or None if an error occurs.
        """
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }

        try:
            with socket.create_connection((self._host, self._port)) as sock:
                sock.sendall(json.dumps(request).encode() + b"\n")
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\n" in chunk:
                        break
                response_str = response.decode().strip()
                response_json = json.loads(response_str)
                if "error" in response_json:
                    print(f"RPC Error: {response_json['error']}")
                    return None
                return response_json["result"]
        except (socket.error, json.JSONDecodeError) as e:
            print(f"Socket request failed: {e}")
            return None

    def _get_utxos_by_scripthash(self, scripthash):
        """
        Retrieve the list of UTXOs for a given scripthash.

        - `scripthash` - Scripthash to query

        Returns a list of UTXOs, or None if an error occurs.
        """
        result = self._socket_request("blockchain.scripthash.listunspent", [scripthash])
        return result

    def __str__(self):
        """
        Return a string representation of the JsonRpcElectrsClient instance.
        """
        return f"JsonRpcElectrsClient(host={self._host}, port={self._port})"
