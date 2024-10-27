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

BACKUP_FILENAME = ".erebos_bckp"


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
        "-o",
        "--output",
        default=os.getcwd(),
        help="Output directory" "(default: current directory)",
    )
    parser.add_argument(
        "port",
        default=8000,
        type=int,
        nargs="?",
        help="bind to this port " "(default: %(default)s)",
    )
    parser.add_argument(
        "--clean", action="store_true", help="Clean generated fraction files"
    )
    parser.add_argument(
        "--rm-backup", action="store_true", help="Remove the generated backup file"
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


def handle_cleanup(fractionator: Fractionator, backup_path: str) -> None:
    """Clean up fractions and remove backup file if necessary."""
    if os.path.exists(backup_path):
        fractionator.load_backup(backup_path)
        fractionator.clean_fractions()
        try:
            os.remove(backup_path)
            logging.info(f"Backup file '{backup_path}' removed.")
        except FileNotFoundError:
            logging.critical(f"Backup file '{backup_path}' not found.")
    else:
        logging.warning(f"No file found at '{backup_path}'.")


if __name__ == "__main__":
    # ensure dual-stack is not disabled; ref #38907
    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            return super().server_bind()

        def finish_request(self, request, client_address):
            self.RequestHandlerClass(
                request, client_address, self, directory=args.output
            )

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Erebos Server: Prepares and stages the LKM over HTTP"
    )
    args = handle_args(parser)

    # Finalize the output/backup paths
    out_path = os.path.abspath(args.output)
    backup_path = os.path.join(out_path, BACKUP_FILENAME)

    # Initialize the fractionator
    fractionator = Fractionator(out_path, generate_aes_key())


    handle_cleanup(fractionator, backup_path)
    if args.clean:
        sys.exit(0)

    # Set up Fractionator with the provided file path
    file_path = validate_lkm_object_file(args.file)
    fractionator.file_path = file_path
    # Prepare the fractions
    fractionator.finalize(backup_path)

    # Start the server for staging fractions
    start_server(ServerClass=DualStackServer, port=args.port, bind=args.bind, aes_key=fractionator.key)
