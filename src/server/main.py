"""
Erebos server, accountable for preparing and staging the chunks of the given object file
"""
import argparse
import contextlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer, test
import logging
import os
import secrets
import socket
from lkm_parser import LKM

logging.basicConfig(
    format='[%(levelname)s: %(funcName)s] %(message)s',
    level=logging.INFO
)

BACKUP_FILENAME = ".erebos_bckp"

# ensure dual-stack is not disabled; ref #38907
class DualStackServer(ThreadingHTTPServer):
    def server_bind(self):
        # suppress exception when protocol is IPv4
        with contextlib.suppress(Exception):
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        return super().server_bind()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--lkm", type=str, help="LKM object file to use", required=True)
    parser.add_argument("-b", "--bind", metavar="ADDRESS",
                        help="bind to this address "
                             "(default: all interfaces)")
    parser.add_argument("-d", "--directory", default=os.getcwd(),
                        help="serve this directory "
                             "(default: current directory)")

    parser.add_argument("port", default=8000, type=int, nargs="?",
                        help="bind to this port "
                             "(default: %(default)s)")
    parser.add_argument("--clean", type=bool, default=False, required=False, help="Clean generated fraction files")
    parser.add_argument("--rm-backup", type=bool, default=False, help="Remove the generated backup file")
    
    args = parser.parse_args()
    
    key = secrets.token_bytes(32)
    logging.debug(f"Generated AES-256 key.")
    
    lkm = LKM(args.lkm, args.directory, key, BACKUP_FILENAME)

    if args.clean:
        lkm.clean_fractions()
        if args.rm_backup: 
            try:
                os.remove(lkm.backup_path)
            except FileNotFoundError:
                logging.warning(f"Failed to remove backup: {lkm.backup_path}, file does not exist.")
        exit(0)
    else: 
        lkm.make_fractions()
        lkm.write_fractions()
        
    # Stage fractions over HTTP
    handler_class = SimpleHTTPRequestHandler
    test(
        HandlerClass=handler_class,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
    )