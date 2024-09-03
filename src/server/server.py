import socket
import sys
import urllib
import contextlib
import html
from http.server import HTTPStatus, SimpleHTTPRequestHandler, ThreadingHTTPServer, test
import io
import os


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
    
def start_server(bind, port):
    test(
        HandlerClass=PlainListingHTTPRequestHandler,
        ServerClass=DualStackServer,
        protocol="HTTP/1.1", # permit keep-alive connections
        port=port,
        bind=bind,
    )