import collections
from .lrc20_types import Lrc20Utxo, BitcoinUtxo
import logging

logger = logging.getLogger(__name__)


class CoinSelector:
    def __init__(
        self, lrc20_utxos: list[Lrc20Utxo] | None, btc_utxos: list[BitcoinUtxo] | None
    ):
        """
        Initialize the CoinSelector with LRC20 and BTC UTXOs.

        - `lrc20_utxos` - List of LRC20 UTXOs available
        - `btc_utxos` - List of Bitcoin UTXOs available
        """
        self._lrc20_utxos = lrc20_utxos
        self._btc_utxos = btc_utxos

    def select_lrc20_utxos(
        self, amounts: dict[str, int]
    ) -> tuple[list[Lrc20Utxo], dict[str, int]]:
        """
        Select LRC20 UTXOs based on the required amounts for each token_pubkey.

        - `amounts` - Dictionary where keys are token_pubkey values and values are amounts of LRC20 required for each token_pubkey

        Returns a tuple containing:
        - `selected_utxos` - List of selected LRC20 UTXOs
        - `change_outputs` - Dictionary where keys are token_pubkey values and values are the change amounts for each token_pubkey
        """
        if not self._lrc20_utxos or len(self._lrc20_utxos) == 0:
            raise ValueError(f"No LRC20 UTXOs available")

        q = collections.deque()
        [q.append(i) for i in self._lrc20_utxos]

        selected_utxos = []
        change_outputs = {}

        for token_pubkey, amount in amounts.items():
            selected_lrc20_amount = 0
            skipped_utxos = []

            while selected_lrc20_amount < amount:
                if len(q) == 0:
                    raise ValueError(
                        f"Not enough LRC20 UTXOs for token_pubkey {token_pubkey}, got {selected_lrc20_amount}, need {amount}"
                    )

                utxo = q.popleft()
                if utxo.receipt.token_pubkey != token_pubkey:
                    skipped_utxos.append(utxo)
                    continue

                selected_utxos.append(utxo)
                selected_lrc20_amount += utxo.receipt.token_amount

            change = selected_lrc20_amount - amount
            if change > 0:
                if token_pubkey not in change_outputs:
                    change_outputs[token_pubkey] = 0
                change_outputs[token_pubkey] += change

            [q.append(i) for i in skipped_utxos]

        return selected_utxos, change_outputs

    def select_btc_utxos(
        self, lrc20_inputs: list[Lrc20Utxo], approximate_fee: int, dust_amount: int
    ) -> list[BitcoinUtxo]:
        """
        Select Bitcoin UTXOs to cover the total amount needed based on the inputs and fees.

        - `lrc20_inputs` - List of LRC20 inputs used in the transaction
        - `approximate_fee` - Estimated fee for the transaction
        - `dust_amount` - Minimum amount considered dust (to be included in the fee calculation)

        Returns a list of selected Bitcoin UTXOs.
        """

        if not self._btc_utxos or len(self._btc_utxos) == 0:
            raise ValueError(f"No BTC UTXOs available for LRC20 operation.")

        selected_amount = 0
        selected_utxos = []
        approximate_fee += dust_amount

        for lrc20_utxo in lrc20_inputs:
            selected_amount += lrc20_utxo.bitcoin_utxo.sats

        while selected_amount < approximate_fee:
            if len(self._btc_utxos) == 0:
                raise ValueError(
                    f"Not enough BTC UTXOs, got {selected_amount}, need {approximate_fee}"
                )

            btc_utxo = self._btc_utxos.pop()
            selected_amount += btc_utxo.sats
            selected_utxos.append(btc_utxo)

        return selected_utxos
