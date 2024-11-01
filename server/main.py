"""
Erebos server, accountable for preparing and staging the chunks of the given object file
"""

import argparse
import contextlib
from http.server import ThreadingHTTPServer
import logging
import os, sys
import secrets
from socket import IPPROTO_IPV6, IPV6_V6ONLY

from fractionator import Fractionator
from server import start_server

logging.basicConfig(
    format="[%(levelname)s: %(funcName)s] %(message)s", level=logging.INFO
)


def handle_args(parser: argparse.ArgumentParser):
    """Configure the given ArgumentParser"""
    parser.add_argument("--file", type=str, help="Path to LKM object file to use")
    parser.add_argument(
        "-b",
        "--bind",
        metavar="ADDRESS",
        help="bind to this address " "(default: all interfaces)",
    )
    parser.add_argument(
        "port",
        default=8000,
        type=int,
        nargs="?",
        help="bind to this port " "(default: %(default)s)",
    )
    return parser.parse_args()


def validate_lkm_object_file(file_path: str) -> str:
    """Validate file type and existence."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' does not exist.")

    _, ext = os.path.splitext(file_path)
    if ext != ".ko":
        raise ValueError(f"Invalid file type: {ext}. Expected a '.ko' file.")

    return os.path.abspath(file_path)


def generate_aes_key() -> bytes:
    """Generate a 256-bit AES key."""
    key = secrets.token_bytes(32)
    logging.debug("Generated AES-256 key.")

    return key


if __name__ == "__main__":
    # ensure dual-stack is not disabled; ref #38907
    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            return super().server_bind()

        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address, self)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Erebos Server: Prepares and stages the LKM over HTTP"
    )
    args = handle_args(parser)

    # Initialize the fractionator
    key = generate_aes_key()
    fractionator = Fractionator(key)

    # Set up Fractionator with the provided file path
    file_path = validate_lkm_object_file(args.file)
    fractionator.file_path = file_path
    # Prepare the fractions
    fractionator.finalize()

    # Start the server for staging fractions
    start_server(
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
        aes_key=fractionator.key,
        fraction_data=fractionator.fractions,
    )
