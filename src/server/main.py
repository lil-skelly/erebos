"""
Erebos server, accountable for preparing and staging the chunks of the given object file
"""

import argparse
import contextlib
import html
from http.server import HTTPStatus, SimpleHTTPRequestHandler, ThreadingHTTPServer, test
import io
import logging
import os
import secrets
import socket
import sys
import urllib

from lkm_parser import LKMFractionator

logging.basicConfig(
    format="[%(levelname)s: %(funcName)s] %(message)s", level=logging.INFO
)

BACKUP_FILENAME = ".erebos_bckp"


# ensure dual-stack is not disabled; ref #38907
class DualStackServer(ThreadingHTTPServer):
    def server_bind(self):
        # suppress exception when protocol is IPv4
        with contextlib.suppress(Exception):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        return super().server_bind()


class PlainListingHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Lists the links to the files in the given directory in plain text"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def list_directory(self, path):
        """
        Helper to produce a directory listing (absent index.html).
        The directory listing (text/plain) contains links to the files in the specified directory.

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            file_list = os.listdir(path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None

        file_list.sort(key=lambda a: a.lower())
        r = []

        try:
            displaypath = urllib.parse.unquote(self.path, errors="surrogatepass")
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)

        displaypath = html.escape(displaypath, quote=False)

        enc = sys.getfilesystemencoding()

        for name in file_list:
            fullname = os.path.join(path, name)
            display_name = f"http://{self.headers["Host"]}{self.path}{fullname}"
            r.append(html.escape(display_name, quote=False))

        encoded = "\n".join(r).encode(enc, "surrogateescape")
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header(f"Content-type", "text/plain; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f


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

    lkm = LKMFractionator(args.file, args.directory, key, BACKUP_FILENAME)

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
    test(
        HandlerClass=PlainListingHTTPRequestHandler,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
    )