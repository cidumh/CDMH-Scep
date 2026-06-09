"""Decrypt OpenSSL traditional PEM (Proc-Type: 4,ENCRYPTED), as used by micromdm/scep."""

from __future__ import annotations

import base64
import hashlib
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .cms.crypto_algs import TripleDES

_ENCRYPTED_PEM = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n"
    rb"Proc-Type: 4,ENCRYPTED\r?\n"
    rb"DEK-Info: ([^\r\n]+)\r?\n\r?\n"
    rb"([A-Za-z0-9+/=\r\n]+)"
    rb"-----END \1-----\r?\n?",
    re.DOTALL,
)


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int) -> bytes:
    """OpenSSL EVP_BytesToKey with MD5 (traditional PEM encryption)."""
    result = b""
    digest = b""
    while len(result) < key_len:
        digest = hashlib.md5(digest + password + salt).digest()
        result += digest
    return result[:key_len]


def _decrypt_des_ede3_cbc(ciphertext: bytes, password: bytes, iv: bytes) -> bytes:
    key = _evp_bytes_to_key(password, iv, 24)
    cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(TripleDES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_traditional_pem(pem_data: bytes, password: bytes = b"") -> bytes:
    """Return decrypted PKCS#1 DER from an OpenSSL encrypted PEM block."""
    match = _ENCRYPTED_PEM.search(pem_data)
    if not match:
        raise ValueError("not an OpenSSL traditional encrypted PEM block")

    dek_info = match.group(2).decode("ascii")
    algo, iv_hex = dek_info.split(",", 1)
    if algo.strip() != "DES-EDE3-CBC":
        raise ValueError(f"unsupported DEK-Info algorithm: {algo}")

    iv = bytes.fromhex(iv_hex.strip())
    ciphertext = base64.b64decode("".join(match.group(3).decode("ascii").split()))
    return _decrypt_des_ede3_cbc(ciphertext, password, iv)


def load_encrypted_pem_private_key(
    pem_data: bytes,
    password: str | None = None,
) -> rsa.RSAPrivateKey:
    """Load micromdm/scep style encrypted ca.key (DES-EDE3-CBC, often empty password)."""
    password_bytes = b"" if password is None else password.encode("utf-8")
    der = decrypt_traditional_pem(pem_data, password_bytes)
    key = serialization.load_der_private_key(der, password=None, backend=default_backend())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("private key must be RSA")
    return key
