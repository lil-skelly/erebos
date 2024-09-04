import socket
import sys
import urllib
import contextlib
import html
from http.server import HTTPStatus, SimpleHTTPRequestHandler, test
import io
import os

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
        contents = []

        enc = sys.getfilesystemencoding()

        server_addr = self.server.server_address
        host, port = server_addr
        for name in file_list:
            display_name = f"http://{host}:{port}{self.path}{name}"
            contents.append(html.escape(display_name, quote=False))

        encoded = "\n".join(contents).encode(enc, "surrogateescape")
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header(f"Content-type", "text/plain; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f


def start_server(ServerClass, port: int=8000, bind=None):
    test(
        HandlerClass=PlainListingHTTPRequestHandler,
        ServerClass=ServerClass,
        protocol="HTTP/1.1",  # permit keep-alive connections
        port=port,
        bind=bind,
    )
