"""
Erebos server, accountable for preparing and staging the chunks of the given object file
"""
import argparse
import contextlib
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer, test
import io
import logging
import os
import secrets
import socket
from typing import Optional
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logging.basicConfig(level=logging.DEBUG)

CHUNK_SIZE = 1024
MAGIC = 0xdeadbeef

@dataclass
class FractionHeader:
    """
    Dataclass representing the header of a fraction.
    To initialize the CRC, create a Fraction object with a header instance as an argument.
    ex.
    >>> header = FractionHeader(MAGIC, 0, IV)
    FractionHeader(magic=[REDACTED], index=0, iv=b'[REDACTED]', crc=0)
    >>> fraction = Fraction(header, data)
    Fraction(header=FractionHeader(magic=[REDACTED], index=0, iv=b'[REDACTED]', crc=261732737), data=b"[REDACTED]")
    """
    magic: int
    index: int
    iv: bytes
    crc: int = field(default=0, init=False)
    
@dataclass
class Fraction:
    """
    Dataclass representing a fraction. 
    It consists of a FractionHeader and data (bytes).
    It automatically creates the CRC32 checksum of the header, using the information found in the header combined with the given data.
    """
    header: FractionHeader
    data: bytes
    
    def __post_init__(self):
        """Post initialization (prepare CRC32 checksum for the header by combining the data)"""
        data = (
            self.header.magic.to_bytes(4, "big") + 
            self.header.index.to_bytes(4, "big") + 
            self.header.iv                       +
            self.data
        )
        
        self.header.crc = zlib.crc32(data)

class LKM:
    def __init__(self, path: str, out_path: str, key: bytes) -> None:
        """Class to handle loading/preparation of a LKM object file to feed to the loader"""
        self._path: str = os.path.abspath(LKM.validate_source_path(path)) # Path to LKM object file
        self._out_path: str = os.path.abspath(LKM.validate_output_path(out_path)) # Path to store generated fractions
        
        self._fractions: list[Fraction] = []
        # I/O
        self._buf_rw_stream: Optional[io.BufferedRandom] = None

        # AES-256 related instance attributes
        self._iv: Optional[bytes] = None
        self._key: Optional[bytes] = LKM.validate_key(key)

    def load(self) -> None:
        """
        Opens a stream to the file specified in self._path.
        If a stream is already open, this function has no effect
        """
        if self._buf_rw_stream is None or self._buf_rw_stream.closed:
            logging.info(f"[info: load] Opened buffered stream to {self._path}.")  
            self._buf_rw_stream = open(self._path, "rb+")
            return
        
        logging.info("[info: load] an open stream already exists.")
        
    def _make_fraction(self, index: int) -> None:
        if not isinstance(index, int): 
            raise ValueError(f"index must be an integer (got `{type(index)}`)")
        # Open a stream to the file and read a chunk
        self.load()
        data = self._buf_rw_stream.read(CHUNK_SIZE) # don't use peek, as it does not advance the position in the file
        logging.debug("[debug: _make_fraction] Read chunk from stream.")
        
        # Generate an IV and encrypt the chunk
        self._iv = secrets.token_bytes(16) # initialization vector for AES-256 encryption
        encrypted_data = self.do_aes_operation(data, True) # encrypt chunk
        logging.info("[info: _make_fraction] Encrypted chunk data using AES-256")
        
        # Create a fraction instance and add it to self._fractions
        header = FractionHeader(
            MAGIC,
            1,
            self._iv
        )
        logging.debug(f"[debug: _make_fraction] Created FractionHeader object: {header}")
        fraction = Fraction(header, encrypted_data)
        logging.debug(f"[debug: _make_fraction] Created Fraction object: {fraction}")
        self._fractions.append(fraction)
        logging.info(f"[info: _make_fraction] Created fraction #{fraction.header.index}")
        
    def make_fractions(self) -> None: ...
    """Iterate through the LKM object file specified in self._path and generate Fraction objects"""
    
    def write_fractions(self) -> None: ...
    """Convert the fraction objects to pure bytes and write them in the appropriate directory (self._out)"""
        
    def do_aes_operation(self, data: bytes, op: bool) -> bytes:
        """Perform an AES-256 operation on given data (encryption [op=True]/decryption [op=False])"""
        if not self._key or not self._iv:
            raise ValueError(f"Missing key or IV (_key:{self._key}, _iv:{self._iv})")
        
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))
        operator = cipher.encryptor() if op else cipher.decryptor()

        return operator.update(data) + operator.finalize()

    def _close_stream(self) -> None:
        """Closes the open stream to self._path and resets self._buf_rw_stream"""
        if isinstance(self._buf_rw_stream, io.BufferedRandom):
            self._buf_rw_stream.close()
            self._buf_rw_stream = None
            logging.info(f"[info: _close_stream] Closed stream to {self._path}.")
            return
        
        logging.info(f"[info: _close_reader] No stream was open.")

    @staticmethod
    def validate_key(key: bytes) -> bytes:
        """Check if key is a valid AES-256 key (32 bytes)"""
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError(f"Invalid AES-256 key. (expected 32 bytes of `{bytes}`, got {len(key)} of `{type(key)}`)")
        return key
    
    @staticmethod
    def validate_generic_path(path: str) -> str:
        if not isinstance(path, str):
            raise ValueError(f"Invalid path (expected `{str}`, got `{type(path)}`).")
        if not os.path.exists(path):
            raise FileNotFoundError(f"{path} does not exist.")
       
        return path
    
    @staticmethod
    def validate_file_ext(path: str, extension: str) -> str:
        """Checks if path is a file and ends with extension"""
        if not path.endswith(".ko") or not os.path.isfile(path):
            raise ValueError(f"{path} is not a valid file.")
        
        return path

    @staticmethod
    def validate_source_path(path: str) -> str:
        """Checks if path is a file with a .ko extension"""
        path = LKM.validate_generic_path(path)
        path = LKM.validate_file_ext(path, ".ko")
        
        return path
    
    @staticmethod
    def validate_output_path(path: str) -> str:
        """Checks if path exists and is a directory"""
        path = LKM.validate_generic_path(path)
        if not os.path.isdir(path):
            raise ValueError(f"Path is not a directory ({path}).")
        
        return path
            
    def __del__(self) -> None:
        self._close_stream()


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
    lkm.load() # not really required
    lkm._make_fraction(1)
    
    # Stage fractions over HTTP
    test(
        HandlerClass=handler_class,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
    )