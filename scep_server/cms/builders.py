import os
from typing import List, Tuple, Union
from uuid import uuid4

from asn1crypto import x509 as asn1x509
from asn1crypto.algos import DigestAlgorithm, DigestAlgorithmId, SignedDigestAlgorithm, SignedDigestAlgorithmId
from asn1crypto.cms import (
    CMSAttribute,
    CMSAttributes,
    CMSVersion,
    CertificateChoices,
    CertificateSet,
    ContentInfo,
    ContentType,
    DigestAlgorithms,
    EnvelopedData,
    IssuerAndSerialNumber,
    OctetString,
    RevocationInfoChoices,
    SignerIdentifier,
    SignerInfo,
    SignerInfos,
    SignedData,
)
from asn1crypto.core import PrintableString
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.asymmetric import rsa

from .asn1 import SCEPCMSAttributeType  # noqa: F401 - registers CMSAttribute patch
from .enums import FailInfo, MessageType, PKIStatus


def certificates_from_asn1(cert_set: CertificateSet) -> List[x509.Certificate]:
    result = []
    for cert in cert_set:
        cert_choice = cert.chosen
        if not isinstance(cert_choice, asn1x509.Certificate):
            continue
        result.append(x509.load_der_x509_certificate(cert_choice.dump(), default_backend()))
    return result


def create_degenerate_pkcs7(*certificates: x509.Certificate) -> ContentInfo:
    certificates_asn1 = [
        asn1x509.Certificate.load(c.public_bytes(serialization.Encoding.DER)) for c in certificates
    ]
    sd_certificates = CertificateSet([CertificateChoices("certificate", asn1) for asn1 in certificates_asn1])
    empty = ContentInfo({"content_type": ContentType("data")})
    sd = SignedData(
        {
            "version": CMSVersion(1),
            "encap_content_info": empty,
            "digest_algorithms": DigestAlgorithms([]),
            "certificates": sd_certificates,
            "signer_infos": SignerInfos([]),
            "crls": RevocationInfoChoices([]),
        }
    )
    return ContentInfo({"content_type": ContentType("signed_data"), "content": sd})


class Signer:
    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        digest_algorithm: str = "sha256",
    ):
        self.certificate = certificate
        self.private_key = private_key
        self.digest_algorithm_id = {
            "sha1": DigestAlgorithmId("sha1"),
            "sha256": DigestAlgorithmId("sha256"),
            "sha512": DigestAlgorithmId("sha512"),
        }[digest_algorithm]
        self.digest_algorithm = DigestAlgorithm({"algorithm": self.digest_algorithm_id})
        self.signed_digest_algorithm = SignedDigestAlgorithm(
            {"algorithm": SignedDigestAlgorithmId("rsassa_pkcs1v15")}
        )

    @property
    def sid(self) -> SignerIdentifier:
        asn1cert = asn1x509.Certificate.load(self.certificate.public_bytes(serialization.Encoding.DER))
        ias = IssuerAndSerialNumber({"issuer": asn1cert.issuer, "serial_number": asn1cert.serial_number})
        return SignerIdentifier("issuer_and_serial_number", ias)

    def sign(
        self,
        content_digest: bytes,
        cms_attributes: List[CMSAttribute],
    ) -> SignerInfo:
        signed_attributes = list(cms_attributes)
        signed_attributes.insert(
            0,
            CMSAttribute({"type": "message_digest", "values": [OctetString(content_digest)]}),
        )
        signed_attributes.insert(
            0,
            CMSAttribute({"type": "content_type", "values": [ContentType("data")]}),
        )
        cms_attrs = CMSAttributes(signed_attributes)

        digest_function = {
            "sha1": hashes.SHA1,
            "sha256": hashes.SHA256,
            "sha512": hashes.SHA512,
        }[self.digest_algorithm_id.native]

        signature = self.private_key.sign(
            cms_attrs.dump(),
            asympad.PKCS1v15(),
            digest_function(),
        )

        return SignerInfo(
            {
                "version": CMSVersion(1),
                "sid": self.sid,
                "digest_algorithm": self.digest_algorithm,
                "signed_attrs": cms_attrs,
                "signature_algorithm": self.signed_digest_algorithm,
                "signature": OctetString(signature),
            }
        )


class PKIMessageBuilder:
    def __init__(self):
        self._signers: List[Signer] = []
        self._cms_attributes: List[CMSAttribute] = []
        self._pki_envelope: EnvelopedData | None = None
        self._certificates = CertificateSet()

    def add_signer(self, signer: Signer) -> "PKIMessageBuilder":
        self._signers.append(signer)
        asn1_certificate = asn1x509.Certificate.load(
            signer.certificate.public_bytes(serialization.Encoding.DER)
        )
        self._certificates.append(CertificateChoices("certificate", asn1_certificate))
        return self

    def message_type(self, message_type: MessageType) -> "PKIMessageBuilder":
        self._cms_attributes.append(
            CMSAttribute({"type": "message_type", "values": [PrintableString(message_type.value)]})
        )
        return self

    def pki_envelope(self, envelope: EnvelopedData) -> "PKIMessageBuilder":
        self._pki_envelope = envelope
        return self

    def pki_status(self, status: PKIStatus, failure_info: FailInfo | None = None) -> "PKIMessageBuilder":
        self._cms_attributes.append(
            CMSAttribute({"type": "pki_status", "values": [PrintableString(status.value)]})
        )
        if status == PKIStatus.FAILURE:
            if failure_info is None:
                raise ValueError("failure_info required for FAILURE status")
            self._cms_attributes.append(
                CMSAttribute({"type": "fail_info", "values": [PrintableString(failure_info.value)]})
            )
        return self

    def sender_nonce(self, nonce: Union[bytes, OctetString, None] = None) -> "PKIMessageBuilder":
        if isinstance(nonce, bytes):
            nonce = OctetString(nonce)
        elif nonce is None:
            nonce = OctetString(os.urandom(16))
        self._cms_attributes.append(CMSAttribute({"type": "sender_nonce", "values": [nonce]}))
        return self

    def recipient_nonce(self, nonce: Union[bytes, OctetString]) -> "PKIMessageBuilder":
        if isinstance(nonce, bytes):
            nonce = OctetString(nonce)
        self._cms_attributes.append(CMSAttribute({"type": "recipient_nonce", "values": [nonce]}))
        return self

    def transaction_id(self, trans_id: Union[str, PrintableString, None] = None) -> "PKIMessageBuilder":
        if isinstance(trans_id, str):
            trans_id = PrintableString(trans_id)
        elif trans_id is None:
            trans_id = PrintableString(str(uuid4()))
        self._cms_attributes.append(CMSAttribute({"type": "transaction_id", "values": [trans_id]}))
        return self

    def finalize(self) -> ContentInfo:
        if self._pki_envelope is None:
            encap_info = ContentInfo({"content_type": ContentType("data")})
            digest_input = b""
        else:
            pkienvelope_content_info = ContentInfo(
                {
                    "content_type": ContentType("enveloped_data"),
                    "content": self._pki_envelope,
                }
            )
            encap_info = ContentInfo(
                {
                    "content_type": ContentType("data"),
                    "content": pkienvelope_content_info.dump(),
                }
            )
            digest_input = pkienvelope_content_info.dump()

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        if digest_input:
            digest.update(digest_input)
        content_digest = digest.finalize()

        signer_infos = SignerInfos(
            signer.sign(content_digest, self._cms_attributes) for signer in self._signers
        )
        da = DigestAlgorithm({"algorithm": DigestAlgorithmId("sha256")})
        sd = SignedData(
            {
                "version": 1,
                "certificates": self._certificates,
                "signer_infos": signer_infos,
                "digest_algorithms": DigestAlgorithms([da]),
                "encap_content_info": encap_info,
            }
        )
        return ContentInfo({"content_type": ContentType("signed_data"), "content": sd})

    def dump(self) -> bytes:
        return self.finalize().dump()
