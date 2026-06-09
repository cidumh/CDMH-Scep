from typing import List

from asn1crypto.cms import ContentInfo, IssuerAndSerialNumber
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .crypto_algs import AES, TripleDES

from .asn1 import SCEPCMSAttributeType  # noqa: F401 - registers CMSAttribute patch
from .enums import MessageType
from .builders import certificates_from_asn1


class SCEPMessage:
    @classmethod
    def parse(cls, raw: bytes) -> "SCEPMessage":
        msg = cls()
        cinfo = ContentInfo.load(raw)
        if cinfo["content_type"].native != "signed_data":
            raise ValueError("expected signed_data content type")

        signed_data = cinfo["content"]
        if len(signed_data["certificates"]) > 0:
            msg._certificates = certificates_from_asn1(signed_data["certificates"])
        else:
            msg._certificates = []

        signer_info = signed_data["signer_infos"][0]
        identifier = signer_info["sid"].chosen
        if not isinstance(identifier, IssuerAndSerialNumber):
            raise ValueError("unsupported signer identifier type")

        if "signed_attrs" in signer_info:
            for signed_attr in signer_info["signed_attrs"]:
                name = SCEPCMSAttributeType.map(signed_attr["type"].native)
                if name == "transaction_id":
                    msg._transaction_id = signed_attr["values"][0].native
                elif name == "message_type":
                    msg._message_type = MessageType(signed_attr["values"][0].native)
                elif name == "sender_nonce":
                    msg._sender_nonce = signed_attr["values"][0].native
                elif name == "recipient_nonce":
                    msg._recipient_nonce = signed_attr["values"][0].native

        msg._signed_data = signed_data["encap_content_info"]["content"]
        return msg

    def __init__(self):
        self._transaction_id: str | None = None
        self._message_type: MessageType | None = None
        self._sender_nonce: bytes | None = None
        self._recipient_nonce: bytes | None = None
        self._signed_data = None
        self._certificates: List[x509.Certificate] = []

    @property
    def certificates(self) -> List[x509.Certificate]:
        return self._certificates

    @property
    def transaction_id(self) -> str | None:
        return self._transaction_id

    @property
    def message_type(self) -> MessageType | None:
        return self._message_type

    @property
    def sender_nonce(self) -> bytes | None:
        return self._sender_nonce

    @property
    def encap_content_info(self) -> ContentInfo:
        return ContentInfo.load(self._signed_data.native)

    def get_decrypted_envelope_data(
        self,
        certificate: x509.Certificate,
        key: rsa.RSAPrivateKey,
    ) -> bytes:
        encap = self.encap_content_info
        if encap["content_type"].native != "enveloped_data":
            raise ValueError("expected enveloped_data in PKI envelope")

        recipient_info = encap["content"]["recipient_infos"][0]
        encrypted_key = recipient_info.chosen["encrypted_key"].native
        plain_key = key.decrypt(encrypted_key, padding=asympad.PKCS1v15())

        encrypted_contentinfo = encap["content"]["encrypted_content_info"]
        algorithm = encrypted_contentinfo["content_encryption_algorithm"]
        encrypted_content_bytes = encrypted_contentinfo["encrypted_content"].native

        if algorithm.encryption_cipher == "aes":
            symkey = AES(plain_key)
        elif algorithm.encryption_cipher == "tripledes":
            symkey = TripleDES(plain_key)
        else:
            raise ValueError(f"unsupported cipher: {algorithm.encryption_cipher}")

        cipher = Cipher(symkey, modes.CBC(algorithm.encryption_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_content_bytes) + decryptor.finalize()

        block_size = AES.block_size if algorithm.encryption_cipher == "aes" else TripleDES.block_size
        unpadder = PKCS7(block_size).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()
