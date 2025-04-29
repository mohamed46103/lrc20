from .db import Lrc20Database
import dbm
from lrc20.lrc20_types import Lrc20Utxo, BitcoinUtxo
from lrc20.utils import serialize_integer, deserialize_integer


LAST_INDEXED_PAGE_KEY = b"last_indexed_page"
LAST_INDEXED_TX_KEY = b"last_indexed_tx_num"
UTXOS_KEY = b"utxos"
TWEAKED_UTXOS_KEY = b"tweaked_utxos"


class PersistentLrc20Storage(Lrc20Database):
    def __init__(self, db_path: str):
        self._db_path = db_path

    def put_lrc20_utxos(self, lrc20_utxos: list[Lrc20Utxo]):
        with dbm.open(self._db_path, "c") as db:
            db[UTXOS_KEY] = Lrc20Utxo.serialize_list(lrc20_utxos)

    def get_lrc20_utxos(self) -> list[Lrc20Utxo]:
        with dbm.open(self._db_path, "c") as db:
            if UTXOS_KEY in db:
                return Lrc20Utxo.deserialize_list(db[UTXOS_KEY])
            return []

    def put_tweaked_utxos(self, tweaked_utxos: list[BitcoinUtxo]):
        with dbm.open(self._db_path, "c") as db:
            db[TWEAKED_UTXOS_KEY] = BitcoinUtxo.serialize_list(tweaked_utxos)

    def get_tweaked_utxos(self) -> list[BitcoinUtxo]:
        with dbm.open(self._db_path, "c") as db:
            if TWEAKED_UTXOS_KEY in db:
                return BitcoinUtxo.deserialize_list(db[TWEAKED_UTXOS_KEY])
            return []

    def put_last_synced_page_num(self, page_num: int):
        with dbm.open(self._db_path, "c") as db:
            db[LAST_INDEXED_PAGE_KEY] = serialize_integer(page_num)

    def get_last_synced_page_num(self) -> int:
        with dbm.open(self._db_path, "c") as db:
            if LAST_INDEXED_PAGE_KEY in db:
                return deserialize_integer(db[LAST_INDEXED_PAGE_KEY])
            return 0

    def put_last_synced_tx_num(self, tx_num: int):
        with dbm.open(self._db_path, "c") as db:
            db[LAST_INDEXED_TX_KEY] = serialize_integer(tx_num)

    def get_last_synced_tx_num(self) -> int:
        with dbm.open(self._db_path, "c") as db:
            if LAST_INDEXED_TX_KEY in db:
                return deserialize_integer(db[LAST_INDEXED_TX_KEY])
            return 0
