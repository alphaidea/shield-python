"""RFC 6238 TOTP codes and authenticator provisioning URIs."""

import base64
import hmac
import time
from dataclasses import dataclass
from datetime import datetime
from secrets import token_bytes
from typing import Literal
from urllib.parse import quote, urlencode

Algorithm = Literal["SHA1", "SHA256", "SHA512"]
DEFAULT_ALGORITHM: Algorithm = "SHA1"
DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_SKEW = 1
DEFAULT_SECRET_LENGTH = 20


@dataclass(frozen=True)
class Options:
    algorithm: Algorithm = DEFAULT_ALGORITHM
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD
    skew: int = DEFAULT_SKEW

    def __post_init__(self) -> None:
        if not (
            self.algorithm in ("SHA1", "SHA256", "SHA512")
            and self.digits in (6, 8)
            and 1 <= self.period <= 86400
            and 0 <= self.skew <= 10
        ):
            raise ValueError("invalid TOTP options")


def _encode(key: bytes) -> str:
    return base64.b32encode(key).decode("ascii").rstrip("=")


def _decode(secret: str) -> bytes:
    if not secret.isascii() or len(secret) > 205:
        raise ValueError("invalid TOTP secret")
    encoded = secret.upper()
    key = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
    if not 16 <= len(key) <= 128 or _encode(key) != encoded:
        raise ValueError("TOTP secret must be canonical unpadded Base32 of 16..128 bytes")
    return key


def _counter(at: datetime | int | float | None, period: int) -> int:
    if isinstance(at, datetime):
        if at.utcoffset() is None:
            raise ValueError("TOTP datetime must be timezone-aware")
        at = at.timestamp()
    if at is None:
        at = time.time()
    if not 0 <= at < 2**63:
        raise ValueError("invalid TOTP Unix timestamp")
    return int(at) // period


def _code(key: bytes, counter: int, options: Options) -> str:
    digest = hmac.digest(key, counter.to_bytes(8, "big"), options.algorithm.lower())
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 10**options.digits:0{options.digits}d}"


def generate_secret() -> str:
    return _encode(token_bytes(DEFAULT_SECRET_LENGTH))


def generate(
    secret: str, at: datetime | int | float | None = None, *, options: Options = Options()
) -> str:
    return _code(_decode(secret), _counter(at, options.period), options)


def verify(
    secret: str, code: str, at: datetime | int | float | None = None, *,
    options: Options = Options(),
) -> bool:
    key = _decode(secret)
    counter = _counter(at, options.period)
    if len(code) != options.digits or not code.isascii() or not code.isdigit():
        return False
    matches = False
    for candidate in range(max(0, counter - options.skew), counter + options.skew + 1):
        matches |= hmac.compare_digest(code, _code(key, candidate, options))
    return matches


def uri(secret: str, issuer: str, account: str, *, options: Options = Options()) -> str:
    key = _decode(secret)
    if not issuer.strip() or not account.strip() or ":" in issuer + account:
        raise ValueError("TOTP issuer and account must be non-empty and contain no colon")
    label = quote(issuer, safe="$&+@=") + ":" + quote(account, safe="$&+@=")
    query = urlencode({
        "algorithm": options.algorithm,
        "digits": options.digits,
        "issuer": issuer,
        "period": options.period,
        "secret": _encode(key),
    })
    return f"otpauth://totp/{label}?{query}"
