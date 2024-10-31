import sys
from http.server import (
    HTTPStatus,
    SimpleHTTPRequestHandler,
    ThreadingHTTPServer,
    _get_best_family,
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import logging
from collections import defaultdict

from queue import Queue, Empty


class ErebosHTTPRequestHandler(SimpleHTTPRequestHandler):
    server_aes_key: bytes = b""
    fraction_data: list[bytes] = []
    _stream_map = defaultdict(Queue)

    @property
    def fraction_num(self) -> int:
        return len(self.fraction_data)

    def get_stream_queue(self) -> Queue:
        """
        Accesses the stream map for the current client-specific queue, ensuring a unique
        queue for each client IP.
        """
        client_ip = self.address_string()
        if client_ip not in self._stream_map:
            queue = self._stream_map[client_ip]
            for fraction in self.fraction_data or []:
                if not queue.full():
                    queue.put(fraction)
        return self._stream_map[client_ip]

    def do_GET(self):
        """Serve a GET request."""
        if self.path == "/stream":
            self.handle_stream_endpoint()
        elif self.path == "/size":
            self.handle_size_endpoint()
        else:
            self.send_error(404, f"{self.path} does not exist")

    def handle_stream_endpoint(self):
        """Handles the /stream endpoint, sending the next fraction to the client."""
        queue = self.get_stream_queue()

        try:
            data = queue.get(timeout=1)  # get next fraction
        except Empty:
            self.send_error(404, "No data available")
            return

        self._send_response(data)

    def handle_size_endpoint(self):
        """Handles the /size endpoint, sending the number of fractions."""
        data = str(self.fraction_num).encode()
        self._send_response(data)

    def _send_response(self, data: bytes):
        """Send a response with given data."""
        try:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionError, BrokenPipeError):
            # Client disconnected or network issue
            logging.error("Connection error: Client may have disconnected.")
        except Exception as e:
            logging.error(f"Unexpected error while sending response: {e}")

    def finish(self):
        """Called after each request and handles cleanup if a client has disconnected"""
        client_ip = self.address_string()
        # Remove the clients queue from the stream map
        if (
            self.headers.get("Connection", "") == "close"
            and client_ip in self._stream_map
        ):
            logging.info(
                f"[{client_ip}] Disconnected. Wasted ~{self.get_stream_queue().qsize()} fractions."
            )
            del self._stream_map[client_ip]
        super().finish()

    def do_POST(self):
        """Handle POST requests to encrypt and send the AES key."""
        # Read the content length and the raw data from the POST request
        content_length = int(
            self.headers.get("Content-Length", 0)
        )  # Get the size of data
        if not content_length:
            self.send_error(400, "No data in request body")
            logging.error("No data found in request body")
            return

        public_key_pem = self.rfile.read(
            content_length
        )  # Read the request body (bytes)

        # Load the public key provided by the client
        try:
            client_public_key = serialization.load_pem_public_key(public_key_pem)
        except Exception as e:
            self.send_error(400, f"Invalid public key format: {str(e)}")
            logging.error(f"Received invalid public key format from client: {str(e)}")
            return

        # Encrypt the AES key with the client's RSA public key
        try:
            encrypted_aes_key = client_public_key.encrypt(
                self.server_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            base64_encoded_aes_key = base64.b64encode(encrypted_aes_key)
        except Exception as e:
            self.send_error(500, f"Encryption failed: {str(e)}")
            logging.error(f"Failed to encrypt the AES key: {str(e)}")
            return

        # Send HTTP response with the encrypted AES key
        self._send_response(base64_encoded_aes_key)
        logging.info(f"Successfully sent encrypted AES key to the client.")


def serve(
    HandlerClass,
    aes_key: bytes,
    fraction_data: list[bytes],
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
    HandlerClass.fraction_data = fraction_data

    with ServerClass(addr, HandlerClass) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f"[{host}]" if ":" in host else host
        logging.info(
            f"Serving HTTP on {host} port {port} " f"(http://{url_host}:{port}/) ..."
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.error("Keyboard interrupt received, exiting.")
            sys.exit(0)


def start_server(
    ServerClass, aes_key: bytes, fraction_data: list[bytes], port: int = 8000, bind=None
):
    serve(
        HandlerClass=ErebosHTTPRequestHandler,
        ServerClass=ServerClass,
        protocol="HTTP/1.1",  # permit keep-alive connections
        port=port,
        bind=bind,
        aes_key=aes_key,
        fraction_data=fraction_data,
    )
