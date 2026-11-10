"""Authenticated AES-GCM."""

from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._encoding import decode_base64, encode_base64

KEY_SIZE_128 = 16
KEY_SIZE_192 = 24
KEY_SIZE_256 = 32
_NONCE_SIZE = 12
_TAG_SIZE = 16
_PREFIX = "v1:"


def _seal(key: bytes, data: bytes, aad: bytes | None = None) -> bytes:
    nonce = token_bytes(_NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _open(key: bytes, data: bytes, aad: bytes | None = None) -> bytes:
    if len(data) < _NONCE_SIZE + _TAG_SIZE:
        raise ValueError("invalid GCM ciphertext length")
    return AESGCM(key).decrypt(data[:_NONCE_SIZE], data[_NONCE_SIZE:], aad)


def gcm_encrypt(key: bytes, data: bytes) -> bytes:
    return _seal(key, data)


def gcm_decrypt(key: bytes, data: bytes) -> bytes:
    return _open(key, data)


def gcm_encrypt_string(key: str, data: str) -> str:
    return _PREFIX + encode_base64(gcm_encrypt(key.encode(), data.encode()))


def gcm_decrypt_string(key: str, data: str) -> str:
    return gcm_decrypt(key.encode(), decode_base64(data, _PREFIX)).decode()


encrypt = gcm_encrypt
decrypt = gcm_decrypt
encrypt_string = gcm_encrypt_string
decrypt_string = gcm_decrypt_string
