import base64
import binascii


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str, prefix: str = "") -> bytes:
    if not data.startswith(prefix):
        raise ValueError("unsupported ciphertext version")
    encoded = data[len(prefix):].replace("\r", "").replace("\n", "")
    return base64.b64decode(encoded, validate=True)


def decode_hex(data: str) -> bytes:
    return binascii.unhexlify(data)
