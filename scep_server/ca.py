import datetime
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .pem_legacy import load_encrypted_pem_private_key

logger = logging.getLogger(__name__)

_ENCRYPTED_PEM_MARKER = b"Proc-Type: 4,ENCRYPTED"


class FileDepot:
    """Simple file-based CA depot, similar to micromdm/scep file depot."""

    def __init__(self, depot_path: str | Path):
        self.depot_path = Path(depot_path)
        self.depot_path.mkdir(parents=True, exist_ok=True)
        self._serial_file = self.depot_path / "serial.txt"
        self._ca_cert_file = self.depot_path / "ca.pem"
        self._ca_key_file = self.depot_path / "ca.key"

    @property
    def exists(self) -> bool:
        return self._ca_cert_file.exists() and self._ca_key_file.exists()

    @property
    def serial(self) -> int:
        if not self._serial_file.exists():
            return 0
        return int(self._serial_file.read_text(encoding="utf-8").strip())

    @serial.setter
    def serial(self, value: int) -> None:
        self._serial_file.write_text(str(value), encoding="utf-8")

    def load_ca(self, password: str | None = None) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        cert_data = self._ca_cert_file.read_bytes()
        key_data = self._ca_key_file.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        if _ENCRYPTED_PEM_MARKER in key_data:
            # micromdm/scep 始终用 EncryptPEMBlock 加密；空密码时 cryptography 无法直接加载
            try:
                key = load_encrypted_pem_private_key(key_data, password=password)
                if password is None:
                    logger.info("Loaded encrypted ca.key with empty password (micromdm/scep default)")
                return cert, key
            except Exception as exc:
                raise ValueError(
                    "无法解密 CA 私钥 ca.key。"
                    " micromdm/scep 未指定 -key-password 时默认为空密码，请省略 --capass 或使用 --capass（无值）。"
                    " 若创建时设置过 -key-password，请用 --capass \"你的密码\"。"
                ) from exc

        key_password: bytes | None = None
        if password is not None:
            key_password = password.encode("utf-8")

        key = serialization.load_pem_private_key(
            key_data, password=key_password, backend=default_backend()
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("CA private key must be RSA")
        return cert, key

    def init_ca(
        self,
        common_name: str = "SCEP CA",
        organization: str = "scep-ca",
        country: str = "CN",
        key_size: int = 2048,
        years: int = 10,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        if self.exists:
            raise FileExistsError(f"CA already exists in {self.depot_path}")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365 * years))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        self._ca_key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self._ca_cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.serial = 0

        logger.info("Created new CA: CN=%s in %s", common_name, self.depot_path)
        return cert, private_key

    def get_or_create_ca(
        self,
        common_name: str = "SCEP CA",
        organization: str = "scep-ca",
        country: str = "CN",
        ca_password: str | None = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        if self.exists:
            return self.load_ca(password=ca_password)
        return self.init_ca(common_name=common_name, organization=organization, country=country)

    def sign_csr(
        self,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        csr: x509.CertificateSigningRequest,
        validity_days: int = 365,
    ) -> x509.Certificate:
        serial = self.serial + 1
        now = datetime.datetime.now(datetime.timezone.utc)

        common_name = "SCEP Client"
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = attr.value
                break

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        issued_dir = self.depot_path / "issued"
        issued_dir.mkdir(exist_ok=True)
        issued_path = issued_dir / f"{serial}.pem"
        issued_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.serial = serial
        logger.info("Issued certificate serial=%s CN=%s", serial, common_name)
        return cert
