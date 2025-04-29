from .db import Lrc20Database
from ..lrc20_types import Lrc20Utxo, BitcoinUtxo


class InMemoryLrc20Storage(Lrc20Database):
    def __init__(self):
        self._lrc20_utxos = []
        self._tweaked_utxos = []
        self._last_synced_page_num = 0
        self._last_synced_tx_num = 0

    def put_lrc20_utxos(self, lrc20_utxos: list[Lrc20Utxo]):
        self._lrc20_utxos = lrc20_utxos

    def get_lrc20_utxos(self) -> list[Lrc20Utxo]:
        return self._lrc20_utxos

    def put_tweaked_utxos(self, tweaked_utxos: list[BitcoinUtxo]):
        self._tweaked_utxos = tweaked_utxos

    def get_tweaked_utxos(self) -> list[BitcoinUtxo]:
        return self._tweaked_utxos

    def put_last_synced_page_num(self, page_num: int):
        self._last_synced_page_num = page_num

    def get_last_synced_page_num(self) -> int:
        return self._last_synced_page_num

    def put_last_synced_tx_num(self, tx_num: int):
        self._last_synced_tx_num = tx_num

    def get_last_synced_tx_num(self) -> int:
        return self._last_synced_tx_num
