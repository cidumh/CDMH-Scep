import logging
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .ca import FileDepot
from .cms.builders import PKIMessageBuilder, Signer, create_degenerate_pkcs7
from .cms.enums import FailInfo, MessageType, PKIStatus
from .cms.envelope import PKCSPKIEnvelopeBuilder
from .cms.message import SCEPMessage
from .csrsigner import CSRRequest, DepotCSRSigner, extract_challenge_password

logger = logging.getLogger(__name__)

DEFAULT_CAPS = b"Renewal\nSHA-1\nSHA-256\nAES\nDES3\nSCEPStandard\nPOSTPKIOperation"


class SCEPService(Protocol):
    def get_ca_caps(self) -> bytes:
        ...

    def get_ca_cert(self, message: str = "") -> tuple[bytes, int]:
        ...

    def pki_operation(self, data: bytes) -> bytes:
        ...


class Service:
    """SCEP business logic, aligned with micromdm/scep server/service.go."""

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        signer: DepotCSRSigner,
        additional_cas: list[x509.Certificate] | None = None,
    ):
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.signer = signer
        self.additional_cas = additional_cas or []

    def get_ca_caps(self) -> bytes:
        return DEFAULT_CAPS

    def get_ca_cert(self, message: str = "") -> tuple[bytes, int]:
        del message
        if self.additional_cas:
            certs = [self.ca_cert, *self.additional_cas]
            degenerate = create_degenerate_pkcs7(*certs)
            return degenerate.dump(), len(certs)
        return self.ca_cert.public_bytes(serialization.Encoding.DER), 1

    def pki_operation(self, data: bytes) -> bytes:
        req = SCEPMessage.parse(data)
        logger.info(
            "PKIOperation message_type=%s transaction_id=%s",
            req.message_type,
            req.transaction_id,
        )

        if req.message_type not in (MessageType.PKCSReq, MessageType.RenewalReq):
            return self._fail_response(req, FailInfo.BadRequest)

        try:
            der_req = req.get_decrypted_envelope_data(self.ca_cert, self.ca_key)
            csr = x509.load_der_x509_csr(der_req, default_backend())
            challenge = extract_challenge_password(csr.tbs_certrequest_bytes)
            csr_req = CSRRequest(
                csr=csr,
                csr_bytes=csr.tbs_certrequest_bytes,
                message_type=req.message_type,
                challenge_password=challenge,
            )
            new_cert = self.signer.sign_csr(csr_req)
            if new_cert is None:
                raise ValueError("no signed certificate")
        except Exception as exc:
            logger.warning("failed to sign CSR: %s", exc)
            return self._fail_response(req, FailInfo.BadRequest)

        return self._success_response(req, new_cert)

    def _fail_response(self, req: SCEPMessage, fail_info: FailInfo) -> bytes:
        signer = Signer(self.ca_cert, self.ca_key, "sha256")
        builder = (
            PKIMessageBuilder()
            .message_type(MessageType.CertRep)
            .transaction_id(req.transaction_id)
            .pki_status(PKIStatus.FAILURE, fail_info)
            .add_signer(signer)
        )
        if req.sender_nonce:
            builder.recipient_nonce(req.sender_nonce)
        return builder.dump()

    def _success_response(self, req: SCEPMessage, new_cert: x509.Certificate) -> bytes:
        degenerate = create_degenerate_pkcs7(new_cert, self.ca_cert)
        if not req.certificates:
            raise ValueError("client certificate required for response encryption")

        envelope = (
            PKCSPKIEnvelopeBuilder()
            .encrypt(degenerate.dump(), "aes256")
            .add_recipient(req.certificates[0])
            .finalize()
        )
        signer = Signer(self.ca_cert, self.ca_key, "sha256")
        builder = (
            PKIMessageBuilder()
            .message_type(MessageType.CertRep)
            .transaction_id(req.transaction_id)
            .pki_status(PKIStatus.SUCCESS)
            .pki_envelope(envelope)
            .sender_nonce()
            .add_signer(signer)
        )
        if req.sender_nonce:
            builder.recipient_nonce(req.sender_nonce)
        return builder.dump()


def create_service(
    depot_path: str,
    challenge_password: str | None = None,
    ca_password: str | None = None,
    cert_validity_days: int = 365,
    ca_common_name: str = "SCEP CA",
    ca_organization: str = "scep-ca",
    ca_country: str = "CN",
) -> Service:
    depot = FileDepot(depot_path)
    ca_cert, ca_key = depot.get_or_create_ca(
        common_name=ca_common_name,
        organization=ca_organization,
        country=ca_country,
        ca_password=ca_password,
    )
    signer = DepotCSRSigner(
        depot=depot,
        ca_cert=ca_cert,
        ca_key=ca_key,
        challenge_password=challenge_password,
        validity_days=cert_validity_days,
    )
    return Service(ca_cert=ca_cert, ca_key=ca_key, signer=signer)
