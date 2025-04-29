import lrcdk
import json

from enum import Enum


class Payment:
    """
    Payment defines all the required data that describes a recipient of a LRC20 payment:
    - `token_pubkey_xonly_pubkey` - X-only public key of the TokenPubkey
    - `recipient_pubkey` - Public key of the recipient
    - `lrc20_amount` - Amount of LRC20 tokens to send
    - `btc_amount` - Amount of satoshis to send
    - `is_p2tr` - Is recipient has P2TR address
    """

    def __init__(
        self,
        token_pubkey_xonly_pubkey: str,
        recipient_pubkey: str,
        lrc20_amount: int,
        btc_amount: int,
        is_p2tr: bool = False,
    ):
        """
        Initialize a Payment object with the given details.

        - `token_pubkey_xonly_pubkey` - X-only public key of the TokenPubkey
        - `recipient_pubkey` - Public key of the recipient
        - `lrc20_amount` - Amount of LRC20 tokens to send
        - `btc_amount` - Amount of satoshis to send
        """
        self.token_pubkey_xonly_pubkey = token_pubkey_xonly_pubkey
        self.recipient_pubkey = recipient_pubkey
        self.lrc20_amount = lrc20_amount
        self.btc_amount = btc_amount
        self.is_p2tr = is_p2tr


class Receipt:
    def __init__(self, token_amount: int, token_pubkey: str, inner_key: str):
        """
        Initialize a Receipt object with the given attributes.

        - `token_amount` - TokenAmount component of the receipt
        - `token_pubkey` - TokenPubkey component of the receipt
        - `inner_key` - Key associated with the receipt
        """
        self.token_amount = token_amount
        self.token_pubkey = token_pubkey
        self.inner_key = inner_key

    def to_receipt(self):
        """
        Convert the Receipt object to a lrcdk.ReceiptProof object.

        Returns a lrcdk.ReceiptProof representation of the Receipt.
        """
        return lrcdk.ReceiptProof(self.token_amount, self.token_pubkey, self.inner_key)

    def __repr__(self):
        """
        Return a string representation of the Receipt object.
        """
        return f"Receipt(token_amount={self.token_amount}, token_pubkey={self.token_pubkey}, inner_key={self.inner_key})"

    def serialize(self):
        """
        Serialize the Receipt object to a JSON-encoded byte string.

        Returns the JSON-encoded byte string representation of the Receipt.
        """
        return json.dumps(
            {
                "token_amount": self.token_amount,
                "token_pubkey": self.token_pubkey,
                "inner_key": self.inner_key,
            }
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, data):
        """
        Deserialize a byte string to a Receipt object.

        - `data` - JSON-encoded byte string representing a Receipt

        Returns a Receipt object.
        """
        obj = json.loads(data.decode("utf-8"))
        return cls(obj["token_amount"], obj["token_pubkey"], obj["inner_key"])


class BitcoinUtxo:
    def __init__(self, sats: int, txid: str, vout: int):
        """
        Initialize a BitcoinUtxo object with the given attributes.

        - `sats` - Amount of satoshis
        - `txid` - Transaction ID
        - `vout` - Output index
        """
        self.sats = sats
        self.txid = txid
        self.vout = vout

    def __repr__(self):
        """
        Return a string representation of the BitcoinUtxo object.
        """
        return f"BitcoinUtxo(sats={self.sats}, outpoint={self.txid}:{self.vout})"

    def serialize(self):
        """
        Serialize the BitcoinUtxo object to a JSON-encoded byte string.

        Returns the JSON-encoded byte string representation of the BitcoinUtxo.
        """
        return json.dumps(
            {"sats": self.sats, "txid": self.txid, "vout": self.vout}
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, data):
        """
        Deserialize a byte string to a BitcoinUtxo object.

        - `data` - JSON-encoded byte string representing a BitcoinUtxo

        Returns a BitcoinUtxo object.
        """
        if isinstance(data, dict):
            # If data is already a dictionary, use it directly
            obj = data
        else:
            # Otherwise, assume it's a JSON string and decode it
            obj = json.loads(data.decode("utf-8"))
        return cls(obj["sats"], obj["txid"], obj["vout"])

    @classmethod
    def serialize_list(cls, utxo_list):
        """
        Serialize a list of BitcoinUtxo objects to a JSON-encoded byte string.

        - `utxo_list` - List of BitcoinUtxo objects to serialize

        Returns the JSON-encoded byte string representation of the list.
        """
        return json.dumps(
            [json.loads(utxo.serialize().decode("utf-8")) for utxo in utxo_list]
        ).encode("utf-8")

    @classmethod
    def deserialize_list(cls, data):
        """
        Deserialize a byte string to a list of BitcoinUtxo objects.

        - `data` - JSON-encoded byte string representing a list of BitcoinUtxo objects

        Returns a list of BitcoinUtxo objects.
        """
        obj_list = json.loads(data.decode("utf-8"))
        return [cls(obj["sats"], obj["txid"], obj["vout"]) for obj in obj_list]


class Lrc20UtxoType(Enum):
    Sig = 1
    P2TR = 2
    Empty = 3


class Lrc20Utxo:
    def __init__(
        self, receipt: Receipt, bitcoin_utxo: BitcoinUtxo, type: Lrc20UtxoType
    ):
        """
        Initialize a Lrc20Utxo object with the given Receipt and BitcoinUtxo.

        - `receipt` - Receipt object associated with the Lrc20Utxo
        - `bitcoin_utxo` - BitcoinUtxo object associated with the Lrc20Utxo
        """
        self.receipt = receipt
        self.bitcoin_utxo = bitcoin_utxo
        self.type = type

    def __repr__(self):
        """
        Return a string representation of the Lrc20Utxo object.
        """
        return f"Lrc20Utxo(receipt={self.receipt}, btc_utxo={self.bitcoin_utxo})"

    def serialize(self):
        """
        Serialize the Lrc20Utxo object to a JSON-encoded byte string.

        Returns the JSON-encoded byte string representation of the Lrc20Utxo.
        """
        return json.dumps(
            {
                "receipt": json.loads(self.receipt.serialize().decode("utf-8")),
                "bitcoin_utxo": json.loads(
                    self.bitcoin_utxo.serialize().decode("utf-8")
                ),
                "type": json.dumps(self.type.value),
            }
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, data):
        """
        Deserialize a byte string to a Lrc20Utxo object.

        - `data` - JSON-encoded byte string representing a Lrc20Utxo

        Returns a Lrc20Utxo object.
        """
        obj = json.loads(data.decode("utf-8"))
        return cls(
            Receipt.deserialize(json.dumps(obj["receipt"]).encode("utf-8")),
            BitcoinUtxo.deserialize(obj["bitcoin_utxo"]),
            Lrc20UtxoType(json.loads(obj["type"])),
        )

    @classmethod
    def serialize_list(cls, lrc20_utxo_list):
        """
        Serialize a list of Lrc20Utxo objects to a JSON-encoded byte string.

        - `lrc20_utxo_list` - List of Lrc20Utxo objects to serialize

        Returns the JSON-encoded byte string representation of the list.
        """
        return json.dumps(
            [
                json.loads(lrc20_utxo.serialize().decode("utf-8"))
                for lrc20_utxo in lrc20_utxo_list
            ]
        ).encode("utf-8")

    @classmethod
    def deserialize_list(cls, data):
        """
        Deserialize a byte string to a list of Lrc20Utxo objects.

        - `data` - JSON-encoded byte string representing a list of Lrc20Utxo objects

        Returns a list of Lrc20Utxo objects.
        """
        obj_list = json.loads(data.decode("utf-8"))
        return [
            cls(
                Receipt.deserialize(json.dumps(obj["receipt"]).encode("utf-8")),
                BitcoinUtxo.deserialize(obj["bitcoin_utxo"]),
                Lrc20UtxoType(json.loads(obj["type"])),
            )
            for obj in obj_list
        ]
