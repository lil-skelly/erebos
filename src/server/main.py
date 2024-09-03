"""
Erebos server, accountable for preparing and staging the chunks of the given object file
"""

import argparse
import logging
import os
import secrets

from fractionator import Fractionator
from server import start_server

logging.basicConfig(
    format="[%(levelname)s: %(funcName)s] %(message)s", level=logging.INFO
)

BACKUP_FILENAME = ".erebos_bckp"


def handle_args(parser: argparse.ArgumentParser):
    """Configure the given ArgumentParser"""
    parser.add_argument(
        "--file", type=str, help="Path to LKM object file to use", required=True
    )
    parser.add_argument(
        "-b",
        "--bind",
        metavar="ADDRESS",
        help="bind to this address " "(default: all interfaces)",
    )
    parser.add_argument(
        "-d",
        "--directory",
        default=os.getcwd(),
        help="serve this directory " "(default: current directory)",
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    handle_args(parser)
    args = parser.parse_args()

    key = secrets.token_bytes(32)
    logging.debug(f"Generated AES-256 key.")

    lkm = Fractionator(args.file, args.directory, key, BACKUP_FILENAME)

    if args.clean:
        lkm.clean_fractions()
        if args.rm_backup:
            try:
                os.remove(lkm.backup_path)
            except FileNotFoundError:
                logging.warning(
                    f"Failed to remove backup: {lkm.backup_path}, file does not exist."
                )
        exit(0)
    else:
        lkm.make_fractions()
        lkm.write_fractions()

    # Stage fractions over HTTP
    start_server(args.bind, args.port)
