import sys
import html
from http.server import HTTPStatus, SimpleHTTPRequestHandler, ThreadingHTTPServer, _get_best_family
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import io
import os
import json
import logging

class ErebosHTTPRequestHandler(SimpleHTTPRequestHandler):
    """
    HTTP request handler for erebos
    - Lists the filenames in the given directory in plain text.
    - On POST requests it expects a {"public_key"} field containing an RSA public-key,
    and will respond with a AES key encrypted using the public key 
    """
    server_aes_key: bytes = NotImplemented
    
    def do_POST(self):
        # Read the content length and the raw data from the POST request
        content_length = int(self.headers['Content-Length'])  # Get the size of data
        post_data = self.rfile.read(content_length)  # Read the request body (bytes)

        # Parse the JSON data
        try:
            form = json.loads(post_data.decode())
            public_key_pem = form.get("public_key")
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON format')
            logging.error("Received invalid JSON format from client.")
            return

        if public_key_pem is None:
            self.send_error(400, 'Missing public_key field')
            logging.error("Request is missing the required 'public_key' field.")
            return

        # Load the public key provided by the client
        try:
            client_public_key = serialization.load_pem_public_key(bytes.fromhex(public_key_pem))
        except Exception as e:
            self.send_error(400, f'Invalid public key format: {str(e)}')
            logging.error(f"Received invalid public key format from client: {str(e)}")
            return

        # Encrypt the AES key with the client's RSA public key
        try:
            encrypted_aes_key = client_public_key.encrypt(
                self.server_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            self.send_error(500, f'Encryption failed: {str(e)}')
            logging.error(f"Failed to encrypt the AES key: {str(e)}")
            return

        # Send HTTP response with the encrypted AES key
        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(encrypted_aes_key)))
        self.end_headers()
        self.wfile.write(encrypted_aes_key)
        logging.info("Successfully sent encrypted AES key to the client.")
        
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
            if name != ".erebos_bckp":
                display_name = f"http://{host}:{port}{self.path}{name}"
                contents.append(html.escape(display_name, quote=False))

        encoded = "\n".join(contents).encode(enc, "surrogateescape")
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", f"text/plain; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        
        return f


def serve(
        HandlerClass,
        aes_key: bytes,
        ServerClass=ThreadingHTTPServer,
        protocol="HTTP/1.0", 
        port=8000,
        bind=None,
    ):
    """
    Serve the HTTP request handler class. 

    This runs an HTTP server on port 8000 (or the port argument).
    """
    ServerClass.address_family, addr = _get_best_family(bind, port)
    
    HandlerClass.protocol_version = protocol
    HandlerClass.server_aes_key = aes_key
    
    with ServerClass(addr, HandlerClass) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f'[{host}]' if ':' in host else host
        logging.info(
            f"Serving HTTP on {host} port {port} "
            f"(http://{url_host}:{port}/) ..."
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.error("Keyboard interrupt received, exiting.")
            sys.exit(0)

def start_server(ServerClass, aes_key: bytes, port: int = 8000, bind=None):
    serve(
        HandlerClass=ErebosHTTPRequestHandler,
        ServerClass=ServerClass,
        protocol="HTTP/1.1",  # permit keep-alive connections
        port=port,
        bind=bind,
        aes_key=aes_key
    )
