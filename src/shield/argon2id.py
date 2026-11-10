"""Peppered Argon2id password hashes in Shield's PHC format."""

import hmac
import re
from dataclasses import dataclass
from secrets import token_bytes

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from ._encoding import decode_base64, encode_base64

DEFAULT_MEMORY = 19456
DEFAULT_ITERATIONS = 2
DEFAULT_PARALLELISM = 1
DEFAULT_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
_PHC = re.compile(
    r"\$argon2id\$v=19\$m=(0|[1-9][0-9]*),t=(0|[1-9][0-9]*),p=(0|[1-9][0-9]*)"
    r"\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)"
)


@dataclass(frozen=True)
class Options:
    memory: int = DEFAULT_MEMORY
    iterations: int = DEFAULT_ITERATIONS
    parallelism: int = DEFAULT_PARALLELISM
    salt_length: int = DEFAULT_SALT_LENGTH
    hash_length: int = DEFAULT_HASH_LENGTH

    def __post_init__(self) -> None:
        if not (
            1 <= self.parallelism <= 16
            and 8 * self.parallelism <= self.memory <= 262144
            and 1 <= self.iterations <= 10
            and 16 <= self.salt_length <= 64
            and 16 <= self.hash_length <= 64
        ):
            raise ValueError("password hash parameters out of range")


def _prehash(pepper: str, password: str) -> bytes:
    if not pepper:
        raise ValueError("password pepper is empty")
    return hmac.digest(pepper.encode(), password.encode(), "sha256")


def _derive(prehash: bytes, salt: bytes, options: Options) -> bytes:
    return Argon2id(
        salt=salt, length=options.hash_length, iterations=options.iterations,
        lanes=options.parallelism, memory_cost=options.memory,
    ).derive(prehash)


def _encode(data: bytes) -> str:
    return encode_base64(data).rstrip("=")


def _decode(encoded: str) -> bytes:
    data = decode_base64(encoded + "=" * (-len(encoded) % 4))
    if _encode(data) != encoded:
        raise ValueError("non-canonical password hash Base64")
    return data


def hash(pepper: str, password: str, options: Options = Options()) -> str:
    prehash = _prehash(pepper, password)
    salt = token_bytes(options.salt_length)
    digest = _derive(prehash, salt, options)
    return (
        f"$argon2id$v=19$m={options.memory},t={options.iterations},p={options.parallelism}"
        f"${_encode(salt)}${_encode(digest)}"
    )


def verify(pepper: str, password: str, encoded: str) -> bool:
    prehash = _prehash(pepper, password)
    match = _PHC.fullmatch(encoded) if len(encoded) <= 256 else None
    if match is None:
        raise ValueError("invalid password hash format")
    memory, iterations, parallelism = map(int, match.groups()[:3])
    salt, digest = map(_decode, match.groups()[3:])
    options = Options(memory, iterations, parallelism, len(salt), len(digest))
    return hmac.compare_digest(_derive(prehash, salt, options), digest)
