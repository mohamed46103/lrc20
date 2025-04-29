from abc import ABC, abstractmethod
from ..lrc20_types import Lrc20Utxo, BitcoinUtxo


class Lrc20Database(ABC):
    @abstractmethod
    def get_lrc20_utxos(self) -> list[Lrc20Utxo]:
        pass

    @abstractmethod
    def put_lrc20_utxos(self, lrc20_utxos: list[Lrc20Utxo]):
        pass

    @abstractmethod
    def get_tweaked_utxos(self) -> list[BitcoinUtxo]:
        pass

    @abstractmethod
    def put_tweaked_utxos(self, tweaked_utxos: list[BitcoinUtxo]):
        pass

    @abstractmethod
    def get_last_synced_page_num(self) -> int:
        pass

    @abstractmethod
    def put_last_synced_page_num(self, page_num: int):
        pass

    @abstractmethod
    def get_last_synced_tx_num(self) -> int:
        pass

    @abstractmethod
    def put_last_synced_tx_num(self, tx_num: int):
        pass
