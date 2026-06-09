import logging
import secrets
from typing import Protocol

from asn1crypto.csr import CertificationRequestInfo
from cryptography import x509

from .ca import FileDepot
from .cms.enums import MessageType

logger = logging.getLogger(__name__)


class CSRSigner(Protocol):
    def sign_csr(self, csr_req: "CSRRequest") -> x509.Certificate | None:
        ...


class CSRRequest:
    def __init__(
        self,
        csr: x509.CertificateSigningRequest,
        csr_bytes: bytes,
        message_type: MessageType,
        challenge_password: str | None = None,
    ):
        self.csr = csr
        self.csr_bytes = csr_bytes
        self.message_type = message_type
        self.challenge_password = challenge_password


def extract_challenge_password(csr_bytes: bytes) -> str | None:
    req_info = CertificationRequestInfo.load(csr_bytes)
    for attr in req_info["attributes"]:
        if attr["type"].native == "challenge_password" and attr["values"]:
            return attr["values"][0].native
    return None


class DepotCSRSigner:
    """Sign CSRs using the local file depot CA."""

    def __init__(
        self,
        depot: FileDepot,
        ca_cert: x509.Certificate,
        ca_key,
        challenge_password: str | None = None,
        validity_days: int = 365,
    ):
        self.depot = depot
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.challenge_password = challenge_password
        self.validity_days = validity_days

    def sign_csr(self, csr_req: CSRRequest) -> x509.Certificate | None:
        if csr_req.message_type == MessageType.PKCSReq and self.challenge_password:
            provided = csr_req.challenge_password or extract_challenge_password(csr_req.csr_bytes)
            if not secrets.compare_digest(provided or "", self.challenge_password):
                raise ValueError("invalid challenge password")

        return self.depot.sign_csr(
            self.ca_cert,
            self.ca_key,
            csr_req.csr,
            validity_days=self.validity_days,
        )
