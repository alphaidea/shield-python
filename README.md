# Shield

A cryptography library for Python 3.11 and later that interoperates with [Go Shield](https://github.com/alphaidea/shield).

Install with `uv add alphaidea-shield`.

- AES-GCM and RSA-OAEP encryption, with hybrid encryption for larger messages.
- RSA-PSS signing and verification.
- Argon2id password hashing and TOTP authentication.
- SHA-256 checksums.
- HMAC-SHA256 computation and verification for bytes, plus stream computation.
- Cryptographically secure random bytes and URL-safe tokens.
- HKDF-SHA256 key derivation.

```python
import shield

key = shield.random_bytes(32)
ciphertext = shield.aes_encrypt(key, b"hello")
plaintext = shield.aes_decrypt(key, ciphertext)
```
