import hashlib
import hmac
import secrets
from typing import BinaryIO, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._encoding import decode_hex


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...
    def hexdigest(self) -> str: ...


def _digest_stream(reader: BinaryIO, digest: _Digest) -> str:
    while chunk := reader.read(65536):
        digest.update(chunk)
    return digest.hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_stream(reader: BinaryIO) -> str:
    return _digest_stream(reader, hashlib.sha256())


def hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.digest(key, data, "sha256").hex()


def hmac_sha256_verify(key: bytes, data: bytes, encoded: str) -> bool:
    if len(encoded) != 64:
        raise ValueError("HMAC-SHA256 must contain 64 hexadecimal characters")
    return hmac.compare_digest(hmac.digest(key, data, "sha256"), decode_hex(encoded))


def hmac_sha256_stream(key: bytes, reader: BinaryIO) -> str:
    return _digest_stream(reader, hmac.new(key, digestmod="sha256"))


def random_bytes(length: int) -> bytes:
    if length <= 0:
        raise ValueError("random byte length must be positive")
    return secrets.token_bytes(length)


def random_token(length: int) -> str:
    if length <= 0:
        raise ValueError("random byte length must be positive")
    return secrets.token_urlsafe(length)


def hkdf_sha256(
    secret: bytes, salt: bytes | None = None, info: str = "", length: int = 32
) -> bytes:
    if not 1 <= length <= 8160:
        raise ValueError("HKDF-SHA256 length must be between 1 and 8160 bytes")
    return HKDF(hashes.SHA256(), length, salt, info.encode()).derive(secret)
