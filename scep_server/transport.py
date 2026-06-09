import base64
import logging
from urllib.parse import unquote

from flask import Flask, Response, request

from .service import SCEPService

logger = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 2 * 1024 * 1024

CERT_CHAIN_HEADER = "application/x-x509-ca-ra-cert"
LEAF_HEADER = "application/x-x509-ca-cert"
PKI_OP_HEADER = "application/x-pki-message"

GET_CA_CAPS = "GetCACaps"
GET_CA_CERT = "GetCACert"
PKI_OPERATION = "PKIOperation"
GET_NEXT_CA_CERT = "GetNextCACert"


def content_header(operation: str, cert_num: int) -> str:
    if operation == GET_CA_CERT:
        return CERT_CHAIN_HEADER if cert_num > 1 else LEAF_HEADER
    if operation == PKI_OPERATION:
        return PKI_OP_HEADER
    return "text/plain"


def extract_message() -> bytes:
    if request.method == "GET":
        msg = request.args.get("message", "")
        operation = request.args.get("operation", "")
        if operation == PKI_OPERATION:
            msg = unquote(msg)
            return base64.b64decode(msg)
        return msg.encode("utf-8")
    return request.get_data(cache=False, as_text=False, parse_form_data=False)[:MAX_PAYLOAD_SIZE]


def create_app(service: SCEPService) -> Flask:
    app = Flask(__name__)

    @app.route("/scep", methods=["GET", "POST"])
    def scep_endpoint():
        operation = request.args.get("operation", "")
        remote = request.remote_addr
        logger.info(
            "SCEP %s %s from %s",
            request.method,
            operation,
            remote,
        )

        try:
            if operation == GET_CA_CAPS:
                data = service.get_ca_caps()
                return Response(data, mimetype="text/plain")

            if operation == GET_CA_CERT:
                message = request.args.get("message", "")
                data, cert_num = service.get_ca_cert(message)
                return Response(data, mimetype=content_header(operation, cert_num))

            if operation == PKI_OPERATION:
                msg = extract_message()
                data = service.pki_operation(msg)
                return Response(data, mimetype=content_header(operation, 0))

            if operation == GET_NEXT_CA_CERT:
                return Response("not implemented", status=501, mimetype="text/plain")

            return Response("unknown SCEP operation", status=404, mimetype="text/plain")
        except Exception as exc:
            logger.exception("SCEP request failed: %s", exc)
            return Response(str(exc), status=500, mimetype="text/plain")

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app
