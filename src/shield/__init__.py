"""Python APIs compatible with the Go Shield library."""

from . import aes as aes, argon2id as argon2id, rsa as rsa, totp as totp
from ._utilities import (
    hkdf_sha256 as hkdf_sha256,
    hmac_sha256 as hmac_sha256,
    hmac_sha256_stream as hmac_sha256_stream,
    hmac_sha256_verify as hmac_sha256_verify,
    random_bytes as random_bytes,
    random_token as random_token,
    sha256 as sha256,
    sha256_stream as sha256_stream,
)
from .aes import (
    decrypt as aes_decrypt,
    decrypt_string as aes_decrypt_string,
    encrypt as aes_encrypt,
    encrypt_string as aes_encrypt_string,
    gcm_decrypt as gcm_decrypt,
    gcm_decrypt_string as gcm_decrypt_string,
    gcm_encrypt as gcm_encrypt,
    gcm_encrypt_string as gcm_encrypt_string,
)
from .argon2id import (
    Options as Argon2idOptions,
    hash as argon2id_hash,
    verify as argon2id_verify,
)
from .rsa import (
    decrypt_hybrid as rsa_decrypt_hybrid,
    decrypt_hybrid_string as rsa_decrypt_hybrid_string,
    decrypt_string as rsa_decrypt_string,
    encrypt_hybrid as rsa_encrypt_hybrid,
    encrypt_hybrid_string as rsa_encrypt_hybrid_string,
    encrypt_string as rsa_encrypt_string,
    generate_key as rsa_generate_key,
    parse_private_key as rsa_parse_private_key,
    parse_public_key as rsa_parse_public_key,
    sign as rsa_sign,
    sign_string as rsa_sign_string,
    verify as rsa_verify,
    verify_string as rsa_verify_string,
)
from .totp import (
    Algorithm as TOTPAlgorithm,
    Options as TOTPOptions,
    generate as totp_generate,
    generate_secret as totp_generate_secret,
    uri as totp_uri,
    verify as totp_verify,
)
