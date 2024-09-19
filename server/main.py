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
    parser.add_argument(
        "--file", type=str, help="Path to LKM object file to use"
    )
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

def handle_cleanup(fractionator: Fractionator, path: str) -> None:
    fractionator.load_backup(backup_path)
    fractionator.clean_fractions()

    try:
        os.remove(path)
    except FileNotFoundError:
        logging.critical(f"{path} is not a valid file.")
        return
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    handle_args(parser)
    args = parser.parse_args()
    
    # ensure dual-stack is not disabled; ref #38907
    class DualStackServer(ThreadingHTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            return super().server_bind()

        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address, self,
                                        directory=args.output)

    key = secrets.token_bytes(32)
    logging.debug(f"Generated AES-256 key.")

    out_path = os.path.abspath(args.output)
    backup_path = os.path.join(out_path, BACKUP_FILENAME) # backup file path
    
    
    fractionator = Fractionator("", out_path, key)
    
    handle_cleanup(fractionator, backup_path)
    if args.clean: exit(0)

    if not args.file:
        raise ValueError("The --file flag is required for this mode.")
    file_path = os.path.abspath(args.file)
    _, ext = os.path.splitext(file_path)
    if ext != ".ko":
        raise ValueError(f"Invalid file type")

    # TODO: Implement path validation
    fractionator._path = args.file
    fractionator.make_fractions()
    fractionator.write_fractions()
    fractionator.save_backup(backup_path)
    

    # lkm.close_stream()

    # Stage fractions over HTTP
    start_server(DualStackServer, args.port, args.bind)
