"""RSA-OAEP, RSA-PSS and the Shield hybrid ciphertext format."""

import re
from secrets import token_bytes

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as backend

from ._encoding import decode_base64, encode_base64
from .aes import _open, _seal

_HEADER = b"SHRSA\x01"
_PREFIX = "hybrid:v1:"
_MINIMUM_BITS = 2048
_PEM = re.compile(
    rb"-----BEGIN ([A-Z ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+)"
    rb"-----END \1-----"
)


def _parse_pem(data: bytes, label: bytes) -> bytes:
    data = data.strip()
    match = _PEM.fullmatch(data)
    if match is None or match[1] != label:
        raise ValueError("invalid RSA key PEM")
    return data


def parse_private_key(data: bytes) -> backend.RSAPrivateKey:
    key = serialization.load_pem_private_key(_parse_pem(data, b"PRIVATE KEY"), password=None)
    if not isinstance(key, backend.RSAPrivateKey):
        raise ValueError("private key is not RSA")
    return key


def parse_public_key(data: bytes) -> backend.RSAPublicKey:
    key = serialization.load_pem_public_key(_parse_pem(data, b"PUBLIC KEY"))
    if not isinstance(key, backend.RSAPublicKey):
        raise ValueError("public key is not RSA")
    return key


def _require_size(bits: int) -> None:
    if bits < _MINIMUM_BITS:
        raise ValueError("RSA key must be at least 2048 bits")


def generate_key(bits: int = _MINIMUM_BITS) -> tuple[str, str]:
    _require_size(bits)
    private = backend.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode("ascii"), public_pem.decode("ascii")


def _oaep(label: bytes | None = None) -> padding.OAEP:
    return padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), label)


def encrypt(key: bytes, data: bytes) -> bytes:
    public = parse_public_key(key)
    _require_size(public.key_size)
    return public.encrypt(data, _oaep())


def decrypt(key: bytes, data: bytes) -> bytes:
    private = parse_private_key(key)
    _require_size(private.key_size)
    return private.decrypt(data, _oaep())


def encrypt_string(key: str, data: str) -> str:
    return encode_base64(encrypt(key.encode(), data.encode()))


def decrypt_string(key: str, data: str) -> str:
    return decrypt(key.encode(), decode_base64(data)).decode()


def encrypt_hybrid(key: bytes, data: bytes) -> bytes:
    public = parse_public_key(key)
    _require_size(public.key_size)
    secret = token_bytes(32)
    header = _HEADER + public.encrypt(secret, _oaep(_HEADER))
    return header + _seal(secret, data, header)


def decrypt_hybrid(key: bytes, data: bytes) -> bytes:
    private = parse_private_key(key)
    _require_size(private.key_size)
    boundary = len(_HEADER) + (private.key_size + 7) // 8
    if len(data) < boundary + 28 or not data.startswith(_HEADER):
        raise ValueError("invalid hybrid ciphertext")
    secret = private.decrypt(data[len(_HEADER):boundary], _oaep(_HEADER))
    if len(secret) != 32:
        raise ValueError("invalid hybrid key length")
    return _open(secret, data[boundary:], data[:boundary])


def encrypt_hybrid_string(key: str, data: str) -> str:
    return _PREFIX + encode_base64(encrypt_hybrid(key.encode(), data.encode()))


def decrypt_hybrid_string(key: str, data: str) -> str:
    return decrypt_hybrid(key.encode(), decode_base64(data, _PREFIX)).decode()


def sign(key: bytes, data: bytes) -> bytes:
    private = parse_private_key(key)
    _require_size(private.key_size)
    algorithm = hashes.SHA256()
    return private.sign(data, padding.PSS(padding.MGF1(algorithm), algorithm.digest_size), algorithm)


def verify(key: bytes, data: bytes, signature: bytes) -> None:
    public = parse_public_key(key)
    _require_size(public.key_size)
    algorithm = hashes.SHA256()
    public.verify(signature, data, padding.PSS(padding.MGF1(algorithm), algorithm.digest_size), algorithm)


def sign_string(key: str, data: str) -> str:
    return encode_base64(sign(key.encode(), data.encode()))


def verify_string(key: str, data: str, signature: str) -> None:
    verify(key.encode(), data.encode(), decode_base64(signature))
