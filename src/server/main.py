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

logging.basicConfig(level=logging.DEBUG)


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
    args = parser.parse_args()
    
    handler_class = SimpleHTTPRequestHandler

    key = secrets.token_bytes(32)
    logging.info(f"[info] Generated AES-256 key: {key}")
    
    lkm = LKM(args.lkm, args.directory, key)
    lkm.open_reading_stream() # not really required
    lkm._make_fraction(1)
    
    
    # Stage fractions over HTTP
    test(
        HandlerClass=handler_class,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
    )