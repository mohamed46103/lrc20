from .coin_select import CoinSelector
import lrcdk
from .lrc20_client import Lrc20Client
from .db.db import Lrc20Database
from .lrc20_types import Payment, Lrc20Utxo, BitcoinUtxo, Lrc20UtxoType
import logging

logger = logging.getLogger(__name__)

MIN_DUST_AMOUNT = 1000


class WalletError(Exception):
    """Base exception for wallet operations"""


class Lrc20BroadcastError(WalletError):
    """Raised when broadcasting LRC20 transaction fails"""


class Lrc20EmulationError(WalletError):
    """Raised when LRC20 transaction emulation fails"""


class BtcBroadcastError(WalletError):
    """Raised when broadcasting BTC transaction fails"""


class WalletSyncError(WalletError):
    """Raised when wallet sync fails"""


class InsufficientFundsError(WalletError):
    """Raised when there are insufficient funds for an operation"""


class TransactionBuildError(WalletError):
    """Raised when transaction building fails"""


class AnnouncementError(WalletError):
    """Raised when creating announcements fails"""


class Wallet:
    """
    Wallet is used to build and sign LRC20 transactions (issue, transfer) and
    announcements (freeze, token_pubkey, transfer ownership).
    """

    def __init__(
        self,
        lrc20_client: Lrc20Client,
        private_key: lrcdk.PyPrivateKey,
        storage: Lrc20Database,
        network: str,
    ):
        """
        Initialize the `LRC20` wallet with the given parameters:
        - `lrc20_client` - LRC20 RPC client
        - `private_key` - WIF Private key
        - `db_path` - Path to the database file
        - `network` - Bitcoin network type
        """

        self._private_key = private_key
        self._public_key = self._private_key.public()
        self._network = network
        self._p2wpkh_address = lrcdk.pubkey_to_p2wpkh(
            self._public_key.public_hex(), network
        )
        self._p2tr_address = lrcdk.pubkey_to_p2tr(
            self._public_key.public_hex(), network
        )
        self._storage = storage
        self._lrc20_client = lrc20_client
        self._lrc20_utxos = storage.get_lrc20_utxos()
        self._tweaked_sats = storage.get_tweaked_utxos()
        self._starting_sync_page = storage.get_last_synced_page_num()
        self._starting_sync_tx = storage.get_last_synced_tx_num()

    def p2tr_address(self) -> str:
        """
        Get wallet's p2tr address.
        """
        return self._p2tr_address

    def p2wpkh_address(self) -> str:
        """
        Get wallet's p2wpkh address.
        """
        return self._p2wpkh_address

    def broadcast_lrc20_tx(
        self, lrc20_tx: lrcdk.PyLrc20Transaction, emulate: bool = True
    ) -> bool:
        """
        Broadcast a LRC20 tx to the network with optional emulate.

        Raises:
            Lrc20BroadcastError: If the transaction fails to broadcast
            Lrc20EmulationError: If the transaction fails emulation
        """
        if emulate:
            emulate_result = self.emulate_lrc20_tx(lrc20_tx)
            if not emulate_result:
                logger.error(f"LRC20 transaction emulation failed: {emulate_result}")
                raise Lrc20EmulationError(
                    f"Transaction emulation failed: {emulate_result}"
                )

        result = self._lrc20_client.send_lrc20_tx(lrcdk.encode_lrc20_tx(lrc20_tx))
        if not result:
            logger.error("Failed to broadcast LRC20 transaction")
            raise Lrc20BroadcastError("Transaction broadcast failed")

        return result

    def broadcast_btc_tx(self, btc_tx: str) -> str:
        """
        Broadcast a BTC tx to the network.

        Raises:
            BtcBroadcastError: If the transaction fails to broadcast
        """
        result = self._lrc20_client._electrs_client.send_raw_tx(btc_tx)
        if not result:
            logger.error("Failed to broadcast BTC transaction")
            raise BtcBroadcastError("Transaction broadcast failed")
        return result

    def emulate_lrc20_tx(self, lrc20_tx: lrcdk.PyLrc20Transaction) -> bool | None:
        """
        Emulate sending a LRC20 tx to the network.
        """
        try:
            result = self._lrc20_client.emulate_lrc20_tx(lrcdk.lrc20_tx_json(lrc20_tx))
            if result is None:
                logger.error("LRC20 transaction emulation returned None")
            return result
        except Exception as e:
            logger.error(f"Error during LRC20 transaction emulation: {str(e)}")
            return None

    async def sync(self):
        """
        Sync the wallet with the LRC20 client, fetching and updating UTXOs.

        Raises:
            WalletSyncError: If the sync operation fails
        """
        try:
            # Filter out spent LRC20 UTXOs
            self._lrc20_utxos = [
                utxo
                for utxo in self._lrc20_utxos
                if not self._lrc20_client._electrs_client.is_spent(
                    utxo.bitcoin_utxo.txid, utxo.bitcoin_utxo.vout
                )
            ]

            # Filter out spent Tweaked UTXOs
            self._tweaked_sats = [
                utxo
                for utxo in self._tweaked_sats
                if not self._lrc20_client._electrs_client.is_spent(utxo.txid, utxo.vout)
            ]

            # Fetch new UTXOs
            (
                self._lrc20_utxos,
                self._tweaked_sats,
                self._starting_sync_page,
                self._starting_sync_tx,
            ) = self._lrc20_client._utxos(
                self._public_key.public_hex(),
                self._lrc20_utxos,
                self._tweaked_sats,
                self._starting_sync_page,
                self._starting_sync_tx,
            )

            # Save the updated state to the database
            self._storage.put_lrc20_utxos(self._lrc20_utxos)
            self._storage.put_tweaked_utxos(self._tweaked_sats)
            self._storage.put_last_synced_page_num(self._starting_sync_page)
            self._storage.put_last_synced_tx_num(self._starting_sync_tx)

        except Exception as e:
            logger.error(f"Error during wallet sync: {str(e)}")
            raise WalletSyncError(f"Wallet sync failed: {str(e)}") from e

    async def issue(
        self,
        payments: list[Payment],
        fee_rate_vb: float,
        drain_tweaked_satoshis: bool = True,
    ) -> lrcdk.PyLrc20Transaction:
        """
        Issue `LRC20` tokens to specified recipients.

        Raises:
            InsufficientFundsError: If there are insufficient funds
            TransactionBuildError: If transaction building fails
        """
        try:
            bitcoin_utxos = self.btc_utxos()
            if not bitcoin_utxos:
                raise InsufficientFundsError("No BTC UTXOs available for issuance")

            coin_selector = CoinSelector([], bitcoin_utxos)
            tx_builder = lrcdk.IssuanceTransactionBuilder(self._private_key.wif())
            approximate_fee = self._calculate_fee(1, len(payments) + 1, fee_rate_vb)
            input_btc_sum = 0
            output_btc_amount = 0

            # Add recipients and calculate BTC amounts
            for payment in payments:
                output_btc_amount += payment.btc_amount

                if payment.is_p2tr:
                    tx_builder.add_taproot_recipient(
                        payment.token_pubkey_xonly_pubkey,
                        payment.recipient_pubkey,
                        payment.lrc20_amount,
                        payment.btc_amount,
                    )
                else:
                    tx_builder.add_recipient(
                        payment.token_pubkey_xonly_pubkey,
                        payment.recipient_pubkey,
                        payment.lrc20_amount,
                        payment.btc_amount,
                    )

            # Drain tweaked satoshis if needed
            if drain_tweaked_satoshis:
                input_btc_sum += self._drain_tweaked_satoshis(tx_builder)

            # Select BTC UTXOs for the transaction
            selected_btc_utxos = (
                []
                if approximate_fee - input_btc_sum <= 0
                else coin_selector.select_btc_utxos(
                    [], approximate_fee, output_btc_amount
                )
            )

            # Add selected UTXOs to the transaction
            input_btc_sum += self._add_selected_utxos(tx_builder, selected_btc_utxos)

            # Set change output if needed
            self._set_change(
                tx_builder, input_btc_sum, approximate_fee, output_btc_amount
            )

            return await tx_builder.finish()
        except ValueError as e:
            logger.error(f"Value error in issuance: {str(e)}")
            raise TransactionBuildError(
                f"Failed to build issuance transaction: {str(e)}"
            ) from e
        except Exception as e:
            logger.error(f"Failed to create issuance transaction: {str(e)}")
            raise TransactionBuildError(
                f"Unexpected error in issuance: {str(e)}"
            ) from e

    async def transfer(
        self,
        payments: list[Payment],
        fee_rate_vb: float,
        drain_tweaked_satoshis: bool = True,
    ) -> lrcdk.PyLrc20Transaction:
        """
        Transfer `LRC20` tokens to specified recipients.

        Raises:
            InsufficientFundsError: If there are insufficient funds
            TransactionBuildError: If transaction building fails
        """
        try:
            bitcoin_utxos = self._lrc20_client._electrs_client.utxos(
                self._p2wpkh_address
            )
            lrc20_utxos, _ = self.lrc20_utxos()

            if not lrc20_utxos:
                raise InsufficientFundsError("No LRC20 UTXOs available for transfer")

            coin_selector = CoinSelector(lrc20_utxos, bitcoin_utxos)
            transfer_tx_builder = lrcdk.TransferTransactionBuilder(
                self._private_key.wif()
            )

            inputs_btc_sum = 0
            if drain_tweaked_satoshis:
                inputs_btc_sum += self._drain_tweaked_satoshis(transfer_tx_builder)

            # Prepare recipient and change outputs
            outputs_num = 1
            outputs_btc_sum = 0
            mapped_amounts = {}
            for payment in payments:
                if payment.token_pubkey_xonly_pubkey not in mapped_amounts:
                    mapped_amounts[payment.token_pubkey_xonly_pubkey] = 0
                mapped_amounts[
                    payment.token_pubkey_xonly_pubkey
                ] += payment.lrc20_amount
            selected_lrc20_utxos, change_outs = coin_selector.select_lrc20_utxos(
                mapped_amounts
            )
            self._add_receipt_inputs(transfer_tx_builder, selected_lrc20_utxos)

            for payment in payments:
                if payment.is_p2tr:
                    transfer_tx_builder.add_taproot_recipient(
                        payment.token_pubkey_xonly_pubkey,
                        payment.recipient_pubkey,
                        payment.lrc20_amount,
                        payment.btc_amount,
                    )
                else:
                    transfer_tx_builder.add_recipient(
                        payment.token_pubkey_xonly_pubkey,
                        payment.recipient_pubkey,
                        payment.lrc20_amount,
                        payment.btc_amount,
                    )
                outputs_btc_sum += payment.btc_amount
                outputs_num += 1

            # Add change outputs
            for token_pubkey, change_amount in change_outs.items():
                if change_amount > 0:
                    outputs_num += 1
                    transfer_tx_builder.add_recipient(
                        token_pubkey,
                        self._public_key.public_hex(),
                        change_amount,
                        MIN_DUST_AMOUNT,
                    )

            # Calculate fees and select additional BTC UTXOs if needed
            approximate_fee = self._calculate_fee(
                len(selected_lrc20_utxos), outputs_num, fee_rate_vb
            )
            selected_btc_utxos = (
                []
                if approximate_fee + outputs_btc_sum - inputs_btc_sum <= 0
                else coin_selector.select_btc_utxos(
                    selected_lrc20_utxos, approximate_fee, outputs_btc_sum
                )
            )
            inputs_btc_sum += self._add_selected_utxos(
                transfer_tx_builder, selected_btc_utxos
            )
            self._set_change(
                transfer_tx_builder, inputs_btc_sum, approximate_fee, outputs_btc_sum
            )

            return await transfer_tx_builder.finish()
        except ValueError as e:
            logger.error(f"Value error in transfer: {str(e)}")
            raise TransactionBuildError(
                f"Failed to build transfer transaction: {str(e)}"
            ) from e
        except Exception as e:
            logger.error(f"Failed to create transfer transaction: {str(e)}")
            raise TransactionBuildError(
                f"Unexpected error in transfer: {str(e)}"
            ) from e

    async def sweep(
        self,
        fee_rate_vb: float,
    ) -> str:
        """
        Create a sweep transaction.

        Raises:
            InsufficientFundsError: If no tweaked satoshis are available
            TransactionBuildError: If transaction building fails
        """
        try:
            sweep_tx_builder = lrcdk.SweepTransactionBuilder(self._private_key.wif())
            _, tweaked_sats = self.lrc20_utxos()

            if not tweaked_sats or len(tweaked_sats) == 0:
                raise InsufficientFundsError("No tweaked sats found to sweep")

            tweaked_utxos_sum = sum(tweaked_utxo.sats for tweaked_utxo in tweaked_sats)
            logger.debug(
                f"Found {len(tweaked_sats)} tweaked UTXOs with total {tweaked_utxos_sum} sats"
            )
            if tweaked_utxos_sum < MIN_DUST_AMOUNT * 2:
                logger.error(
                    f"Total amount {tweaked_utxos_sum} is less than minimum required {MIN_DUST_AMOUNT * 2}"
                )
                raise InsufficientFundsError(
                    f"Total amount {tweaked_utxos_sum} is less than minimum required {MIN_DUST_AMOUNT * 2}"
                )

            self._drain_tweaked_satoshis(sweep_tx_builder)

            return await sweep_tx_builder.sweep(fee_rate_vb)
        except Exception as e:
            logger.error(f"Failed to create sweep transaction: {str(e)}")
            raise TransactionBuildError(
                f"Failed to build sweep transaction: {str(e)}"
            ) from e

    def get_funded_announcement_builder(
        self, fee_rate_vb: float
    ) -> lrcdk.AnnouncementTransactionBuilder:
        """
        Create a funded announcement builder for transactions.

        Returns an instance of `lrcdk.AnnouncementTransactionBuilder` with BTC UTXOs added.
        """
        announcement_builder = lrcdk.AnnouncementTransactionBuilder(
            self._private_key.wif()
        )

        bitcoin_utxos = self.btc_utxos()
        coin_selector = CoinSelector([], bitcoin_utxos)
        approximate_fee = self._calculate_fee(1, 3, fee_rate_vb)

        selected_btc_utxos = coin_selector.select_btc_utxos([], approximate_fee, 0)
        input_btc_sum = self._add_selected_utxos(
            announcement_builder, selected_btc_utxos
        )

        self._set_change(announcement_builder, input_btc_sum, approximate_fee, 0)

        return announcement_builder

    async def freeze(
        self,
        token_pubkey_xonly_pubkey: str,
        outpoint: lrcdk.OutPoint,
        fee_rate_vb: float,
    ) -> lrcdk.PyLrc20Transaction:
        """
        Freeze LRC20 tokens.

        Raises:
            AnnouncementError: If announcement creation fails
        """
        try:
            freeze_tx_builder = self.get_funded_announcement_builder(fee_rate_vb)
            return await freeze_tx_builder.freeze(token_pubkey_xonly_pubkey, outpoint)
        except Exception as e:
            logger.error(f"Failed to create freeze transaction: {str(e)}")
            raise AnnouncementError(
                f"Failed to create freeze announcement: {str(e)}"
            ) from e

    async def token_pubkey_announcement(
        self,
        token_pubkey_xonly_pubkey: str,
        name: str,
        symbol: str,
        decimal: int,
        max_supply: int,
        is_freezable: bool,
        fee_rate_vb: float,
    ) -> lrcdk.PyLrc20Transaction:
        """
        Announce LRC20 token_pubkey.

        Raises:
            AnnouncementError: If announcement creation fails
        """
        try:
            announcement_builder = self.get_funded_announcement_builder(fee_rate_vb)
            return await announcement_builder.token_pubkey(
                token_pubkey_xonly_pubkey,
                name,
                symbol,
                decimal,
                max_supply,
                is_freezable,
            )
        except Exception as e:
            logger.error(f"Failed to create token_pubkey announcement: {str(e)}")
            raise AnnouncementError(
                f"Failed to create token_pubkey announcement: {str(e)}"
            ) from e

    async def transfer_ownership(
        self, token_pubkey_xonly_pubkey: str, new_owner: str, fee_rate_vb: float
    ) -> lrcdk.PyLrc20Transaction:
        """
        Transfer ownership of the wallet.

        Raises:
            AnnouncementError: If announcement creation fails
        """
        try:
            transfer_ownership_builder = self.get_funded_announcement_builder(
                fee_rate_vb
            )
            return await transfer_ownership_builder.transfer_ownership(
                token_pubkey_xonly_pubkey, new_owner
            )
        except Exception as e:
            logger.error(f"Failed to create transfer ownership transaction: {str(e)}")
            raise AnnouncementError(
                f"Failed to create transfer ownership announcement: {str(e)}"
            ) from e

    def lrc20_utxos(self) -> tuple[list[Lrc20Utxo], list[BitcoinUtxo]]:
        return self._lrc20_utxos, self._tweaked_sats

    def lrc20_balances(self) -> dict[str, int]:
        """
        Get the balance of each TokenPubkey in the wallet.

        Returns a dictionary with TokenPubkey public keys as keys and their respective balances as values.
        """
        lrc20_utxos, _ = self.lrc20_utxos()
        balances = {}
        for lrc20_utxo in lrc20_utxos:
            token_pubkey = lrc20_utxo.receipt.token_pubkey
            if token_pubkey not in balances:
                balances[token_pubkey] = 0
            balances[token_pubkey] += lrc20_utxo.receipt.token_amount
        return balances

    def btc_balance(self) -> int:
        """
        Get the total Bitcoin balance, including both regular and tweaked balances.

        Returns a tuple with the regular Bitcoin balance and the tweaked Bitcoin balance.
        """
        bitcoin_utxos_sum = sum(btc_utxo.sats for btc_utxo in self.btc_utxos())
        _, tweaked_utxos = self.lrc20_utxos()
        tweaked_utxos_sum = sum(tweaked_utxo.sats for tweaked_utxo in tweaked_utxos)
        return bitcoin_utxos_sum + tweaked_utxos_sum

    def btc_utxos(self) -> list[BitcoinUtxo]:
        """
        Retrieve the list of Bitcoin UTXOs for the wallet's address.

        Returns a list of Bitcoin UTXOs.
        """
        try:
            utxos = self._lrc20_client._electrs_client.utxos(self._p2wpkh_address)
            if not utxos:
                logger.debug("No BTC UTXOs found for address %s", self._p2wpkh_address)
                return []
            return utxos
        except Exception as e:
            logger.error(f"Error fetching BTC UTXOs: {str(e)}")
            return []

    def _drain_tweaked_satoshis(self, tx_builder):
        """
        Add tweaked UTXOs to the transaction and calculate the total amount of tweaked satoshis used.

        - `tx_builder` - Transaction builder to which tweaked UTXOs are added

        Returns the total amount of tweaked satoshis used.
        """
        sats_sum = 0
        _, tweaked_sats = self.lrc20_utxos()
        for tweaked_out in tweaked_sats:
            tx_hash = self._lrc20_client._electrs_client.get_raw_tx(tweaked_out.txid)
            outpoint = lrcdk.OutPoint(tweaked_out.txid, tweaked_out.vout)
            tweaked_sats_input = lrcdk.BuilderInput.TweakedSatoshis(
                outpoint=outpoint, prev_tx_hash=tx_hash
            )
            tx_builder.add_input(tweaked_sats_input)
            sats_sum += tweaked_out.sats

        self._tweaked_sats.clear()
        return sats_sum

    def _add_selected_utxos(self, tx_builder, selected_utxos):
        """
        Add selected UTXOs to the transaction builder.

        - `tx_builder` - Transaction builder to which selected UTXOs are added
        - `selected_utxos` - List of selected UTXOs to be added as inputs

        Returns the total amount of the selected UTXOs.
        """
        input_btc_sum = 0
        for utxo in selected_utxos:
            tx_hash = self._lrc20_client._electrs_client.get_raw_tx(utxo.txid)
            sats_input = lrcdk.BuilderInput.Satoshis(
                outpoint=lrcdk.OutPoint(utxo.txid, utxo.vout), prev_tx_hash=tx_hash
            )
            tx_builder.add_input(sats_input)
            input_btc_sum += utxo.sats
        return input_btc_sum

    def _add_receipt_inputs(self, transfer_tx_builder, selected_lrc20_utxos):
        """
        Add receipt UTXOs to the transaction builder.

        - `transfer_tx_builder` - Transaction builder to which receipt inputs are added
        - `selected_lrc20_utxos` - List of selected LRC20 UTXOs to be added as inputs
        """
        for lrc20_utxo in selected_lrc20_utxos:
            receipt = lrc20_utxo.receipt
            receipt_proof = lrcdk.ReceiptProof(
                token_amount=receipt.token_amount,
                token_pubkey=receipt.token_pubkey,
                inner_key=receipt.inner_key,
            )
            btc_utxo = lrc20_utxo.bitcoin_utxo
            tx_hash = self._lrc20_client._electrs_client.get_tx(btc_utxo.txid).raw_hex()

            receipt_input = None
            if lrc20_utxo.type == Lrc20UtxoType.Sig:
                receipt_input = lrcdk.BuilderInput.Receipt(
                    outpoint=lrcdk.OutPoint(btc_utxo.txid, btc_utxo.vout),
                    proof=receipt_proof,
                    prev_tx_hash=tx_hash,
                )

            if lrc20_utxo.type == Lrc20UtxoType.P2TR:
                receipt_input = lrcdk.BuilderInput.TaprootReceipt(
                    outpoint=lrcdk.OutPoint(btc_utxo.txid, btc_utxo.vout),
                    proof=receipt_proof,
                    prev_tx_hash=tx_hash,
                )

            transfer_tx_builder.add_input(receipt_input)

    @staticmethod
    def _set_change(tx_builder, input_btc_sum, approximate_fee, btc_amount):
        """
        Set the change output for the transaction.

        - `tx_builder` - Transaction builder to which the change output is added
        - `input_btc_sum` - Total amount of Bitcoin inputs
        - `approximate_fee` - Estimated transaction fee
        - `btc_amount` - Total amount of Bitcoin outputs
        """
        change_amount = input_btc_sum - btc_amount - approximate_fee
        if change_amount > MIN_DUST_AMOUNT:
            tx_builder.set_change_satoshis(int(change_amount))

    @staticmethod
    def _calculate_fee(input_count, output_count, fee_rate_vb):
        """
        Calculate the transaction fee based on input and output counts and fee rate.

        - `input_count` - Number of inputs in the transaction
        - `output_count` - Number of outputs in the transaction
        - `fee_rate_vb` - Fee rate in satoshis per virtual byte

        Returns the calculated fee.
        """
        # Estimate transaction size: each input is 148 bytes, each output is 34 bytes,
        # and the transaction has a fixed overhead of 10 bytes
        tx_size = max(1, input_count) * 148 + output_count * 34 + 10
        return tx_size * fee_rate_vb
