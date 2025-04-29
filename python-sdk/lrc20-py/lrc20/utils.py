import base58
from bech32 import bech32_decode, convertbits
import hashlib


# Serialize an integer
def serialize_integer(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big", signed=True)


# Deserialize an integer
def deserialize_integer(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big", signed=True)


def address_to_scripthash(address: str) -> str:
    script_pubkey = address_to_scriptpubkey(address)
    sha256_hash = hashlib.sha256(bytes.fromhex(script_pubkey)).digest()
    # Reverse the bytes for Electrum protocol
    scripthash = sha256_hash[::-1].hex()
    return scripthash


def address_to_scriptpubkey(address: str) -> str:
    if address.startswith(("1", "m", "n")):
        # P2PKH Address
        h = base58.b58decode_check(address)
        pubkey_hash = h[1:]
        return "76a914" + pubkey_hash.hex() + "88ac"
    elif address.startswith(("3", "2")):
        # P2SH Address
        h = base58.b58decode_check(address)
        script_hash = h[1:]
        return "a914" + script_hash.hex() + "87"
    elif address.startswith(("bc1", "bcrt1", "tb1", "BC1", "TB1")):
        # Bech32 Address
        hrp, data = decode_bech32_address(address)
        if data is None:
            raise ValueError("Invalid Bech32 address")
        witver = data[0]
        witprog = data[1:]
        witprog_bytes = bytes(convertbits(witprog, 5, 8, False))
        if witver > 0:
            # Future versions
            script = (
                "{:02x}{:02x}".format(witver + 0x50, len(witprog_bytes))
                + witprog_bytes.hex()
            )
        else:
            # Version 0 P2WPKH or P2WSH
            script = (
                "{:02x}{:02x}".format(witver, len(witprog_bytes)) + witprog_bytes.hex()
            )
        return script
    else:
        raise ValueError("Unsupported address type")


def decode_bech32_address(address):
    # Determine the human-readable part (hrp)
    if address.lower().startswith("bc1"):
        hrp = "bc"
    elif address.lower().startswith("tb1"):
        hrp = "tb"
    elif address.lower().startswith("bcrt1"):
        hrp = "bcrt"
    else:
        raise ValueError("Invalid Bech32 address prefix")
    decoded = bech32_decode(address)
    if decoded is None:
        raise ValueError("Bech32 decoding failed")
    hrpgot, data = decoded
    return hrpgot, data
