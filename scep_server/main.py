"""SCEP server entry point."""

import argparse
import logging
import sys

from .service import create_service
from .transport import create_app

DEFAULT_PORT = 9001
DEFAULT_DEPOT = "depot"


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python SCEP Server (RFC 8894)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTP listen port")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP listen address")
    parser.add_argument("--depot", default=DEFAULT_DEPOT, help="CA certificate depot path")
    parser.add_argument(
        "--capass",
        nargs="?",
        const="",
        default=None,
        help="CA private key password. 省略则自动尝试空密码(micromdm/scep 默认); 仅写 --capass 表示空密码",
    )
    parser.add_argument("--challenge", default="", help="Optional SCEP challenge password")
    parser.add_argument("--cert-validity", type=int, default=365, help="Issued cert validity in days")
    parser.add_argument("--ca-cn", default="SCEP CA", help="CA common name")
    parser.add_argument("--ca-o", default="scep-ca", help="CA organization")
    parser.add_argument("--ca-c", default="CN", help="CA country")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.debug)

    service = create_service(
        depot_path=args.depot,
        challenge_password=args.challenge or None,
        ca_password=args.capass,
        cert_validity_days=args.cert_validity,
        ca_common_name=args.ca_cn,
        ca_organization=args.ca_o,
        ca_country=args.ca_c,
    )
    app = create_app(service)

    logging.getLogger(__name__).info(
        "SCEP server listening on http://%s:%s/scep",
        args.host,
        args.port,
    )
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
