import os
from typing import Tuple, Union

from asn1crypto.algos import EncryptionAlgorithm, EncryptionAlgorithmId
from asn1crypto.cms import (
    ContentType,
    EncryptedContentInfo,
    EnvelopedData,
    IssuerAndSerialNumber,
    KeyEncryptionAlgorithm,
    KeyEncryptionAlgorithmId,
    KeyTransRecipientInfo,
    RecipientIdentifier,
    RecipientInfo,
    RecipientInfos,
)
from asn1crypto.core import OctetString
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .crypto_algs import AES, TripleDES


class PKCSPKIEnvelopeBuilder:
    def __init__(self):
        self._data: bytes | None = None
        self._encryption_algorithm_id: EncryptionAlgorithmId | None = None
        self._recipients: list[x509.Certificate] = []

    def encrypt(self, data: bytes, algorithm: str = "aes256") -> "PKCSPKIEnvelopeBuilder":
        self._data = data
        algo_map = {
            "3des": "tripledes_3key",
            "aes128": "aes128_cbc",
            "aes256": "aes256_cbc",
        }
        if algorithm not in algo_map:
            raise ValueError(f"unsupported algorithm: {algorithm}")
        self._encryption_algorithm_id = EncryptionAlgorithmId(algo_map[algorithm])
        return self

    def add_recipient(self, certificate: x509.Certificate) -> "PKCSPKIEnvelopeBuilder":
        self._recipients.append(certificate)
        return self

    def _encrypt_data(self, data: bytes) -> Tuple[Union[TripleDES, AES], bytes, bytes]:
        algo = self._encryption_algorithm_id.native
        if algo == "tripledes_3key":
            symkey = TripleDES(os.urandom(24))
            block_size = TripleDES.block_size
            iv = os.urandom(8)
        elif algo == "aes128_cbc":
            symkey = AES(os.urandom(16))
            block_size = AES.block_size
            iv = os.urandom(16)
        elif algo == "aes256_cbc":
            symkey = AES(os.urandom(32))
            block_size = AES.block_size
            iv = os.urandom(16)
        else:
            raise ValueError(f"unsupported algorithm: {algo}")

        cipher = Cipher(symkey, modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(block_size).padder()
        padded = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return symkey, iv, ciphertext

    def _build_recipient_info(self, symmetric_key: bytes, recipient: x509.Certificate) -> RecipientInfo:
        encrypted_symkey = recipient.public_key().encrypt(symmetric_key, asympad.PKCS1v15())
        asn1cert = asn1x509.Certificate.load(recipient.public_bytes(serialization.Encoding.DER))
        ias = IssuerAndSerialNumber(
            {"issuer": asn1cert.issuer, "serial_number": asn1cert.serial_number}
        )
        return RecipientInfo(
            "ktri",
            KeyTransRecipientInfo(
                {
                    "version": 0,
                    "rid": RecipientIdentifier("issuer_and_serial_number", ias),
                    "key_encryption_algorithm": KeyEncryptionAlgorithm(
                        {"algorithm": KeyEncryptionAlgorithmId("rsa")}
                    ),
                    "encrypted_key": encrypted_symkey,
                }
            ),
        )

    def finalize(self) -> EnvelopedData:
        if self._data is None or not self._recipients:
            raise ValueError("data and at least one recipient are required")

        sym_key, iv, ciphertext = self._encrypt_data(self._data)
        eci = EncryptedContentInfo(
            {
                "content_type": ContentType("data"),
                "content_encryption_algorithm": EncryptionAlgorithm(
                    {
                        "algorithm": self._encryption_algorithm_id,
                        "parameters": OctetString(iv),
                    }
                ),
                "encrypted_content": ciphertext,
            }
        )
        recipients = [self._build_recipient_info(sym_key.key, recipient) for recipient in self._recipients]
        return EnvelopedData(
            {
                "version": 1,
                "recipient_infos": RecipientInfos(recipients),
                "encrypted_content_info": eci,
            }
        )
