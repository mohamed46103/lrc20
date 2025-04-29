from abc import ABC, abstractmethod
from ..lrc20_types import BitcoinUtxo
from lrcdk import PyLrc20Transaction as Transaction

DEFAULT_FEE = 1.2


class ElectrsClient(ABC):
    @abstractmethod
    def utxos(self, address: str) -> list[BitcoinUtxo]:
        """
        Retrieve UTXOs for a given Bitcoin address.

        - `address` - Bitcoin address to query

        Returns a list of BitcoinUtxo objects representing the UTXOs for the address, or None if an error occurs.
        """
        pass

    @abstractmethod
    def get_tx(self, txid: str) -> Transaction:
        """
        Retrieve and parse a transaction by its ID.

        - `txid` - Transaction ID to query

        Returns a Transaction object representing the transaction, or None if an error occurs.
        """
        pass

    @abstractmethod
    def get_raw_tx(self, txid: str) -> str:
        """
        Retrieve the raw transaction hex by its ID.

        - `txid` - Transaction ID to query

        Returns the raw transaction hex as a string, or None if an error occurs.
        """
        pass

    @abstractmethod
    def get_fee(self, target: int) -> float:
        """
        Retrieve the fee estimate for a given confirmation target.

        - `target` - Confirmation target in blocks (1-25, 144, 504, 1008)

        Returns the estimated fee for the target, or DEFAULT_FEE if the estimate is not available.
        """
        pass

    @abstractmethod
    def send_raw_tx(self, raw_tx_hex: str):
        """
        Send raw Bitcoin transaction.

        - `raw_tx_hex` - Hex encoded BTC transaction

        Returns the txid if the transaction is broadcasted successfully.
        """
        pass

    @abstractmethod
    def is_spent(self, txid: str, vout: int) -> bool:
        """
        Check if the outpoint is spent.

        - `txid` - Transaction ID to query
        - `vout` - Output index to query

        Returns a boolean value indicating if the output is spent.
        """
        pass
