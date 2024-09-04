import os
import io
from typing import Callable, Optional
import logging
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import utils
from dataclasses import dataclass, field
import zlib
import struct
from typing import Literal


@dataclass
class Fraction:
    """Dataclass to represent a fraction"""

    magic: int
    index: int
    iv: bytes
    _crc: int = field(init=False, repr=False)
    data: bytes

    def header_to_bytes(
        self, endianess: Literal["big", "little"] = "big", crc=True
    ) -> bytes:
        """
        Convert the header information of the fraction to bytes

        endianess: Endianess to use (big, little)
        crc: Include CRC in the returned data (default: True)
        """
        end = ">" if endianess == "big" else "<"
        fmt = f"{end}II16sI" if crc else f"{end}II16s"

        args = [fmt, self.magic, self.index, self.iv]
        if crc:
            args.append(self._crc)

        return struct.pack(*args)

    def calculate_crc(self) -> None:
        """Calculate the CRC checksum of the fraction"""
        crc_data = self.header_to_bytes(crc=False)
        self._crc = zlib.crc32(crc_data)

    @property
    def crc(self) -> int:
        if not self._crc:
            self.calculate_crc()

        return self._crc

    def __post_init__(self) -> None:
        self.calculate_crc()


class Fractionator:
    MAGIC: int = 0xDEADBEEF
    CHUNK_SIZE: int = 8192
    FRACTION_PATH_LEN = 16

    def __init__(
        self, path: str, out_path: str, key: bytes
    ) -> None:
        """Class to handle loading/preparation of a Fractionator object file to feed to the loader"""
        self._path: str = path # Path to LKM object file
        self._out_path: str = out_path # Path to store generated fractions
        
        self._fractions: list[Fraction] = []  # Keep track of the fraction objects
        self.fraction_paths: list[str] = []  # Book-keeping of fraction filenames for cleanup
        # I/O
        self._buf_reader: Optional[io.BufferedReader] = None
        # AES-256 related instance attributes
        self._iv: Optional[bytes] = None  # AES-256 initialization vector
        self._key: Optional[bytes] = Fractionator.validate_aes_key(
            key
        )  # AES-256 cryptographic key

    def open_reading_stream(self) -> None:
        """
        Opens a reading stream to the file specified in self._path.
        If a stream is already open, this function has no effect
        """
        if self._buf_reader is None or self._buf_reader.closed:
            self._buf_reader = open(self._path, "rb")
            logging.debug(f"Opened reading stream to {self._path}.")
            return

    def _make_fraction(self, index: int) -> None:
        """Read from the object-file and generate a fraction"""
        if not isinstance(index, int):
            raise ValueError(f"index must be an integer (got `{type(index)}`)")
        # Open a stream to the file and read a chunk
        self.open_reading_stream()
        data = self._buf_reader.read(
            Fractionator.CHUNK_SIZE
        )  # don't use peek, as it does not advance the position in the file
        
        # Generate an IV and encrypt the chunk
        self._iv = secrets.token_bytes(
            16
        )  # initialization vector for AES-256 encryption
        encrypted_data = self.do_aes_operation(data, True)  # encrypt chunk

        # Create a fraction instance and add it to self._fractions
        fraction = Fraction(
            magic=Fractionator.MAGIC, index=index, iv=self._iv, data=encrypted_data
        )
        self._fractions.append(fraction)
        logging.debug(f"Created fraction #{fraction.index}")

    def make_fractions(self) -> None:
        """Iterate through the Fractionator object file specified in self._path and generate Fraction objects"""
        size = os.path.getsize(self._path)
        num_chunks = (size + Fractionator.CHUNK_SIZE - 1) // Fractionator.CHUNK_SIZE

        logging.info(f"[info: make_fractions] Creating {num_chunks} fractions.")
        for i in range(num_chunks):
            self._make_fraction(i)

    def _write_fraction(self, fraction: Fraction):
        """Write a fraction to a file"""
        path = os.path.join(
            self._out_path, utils.random_string(Fractionator.FRACTION_PATH_LEN)
        )

        with open(path, "wb") as f:
            header_data = fraction.header_to_bytes()
            data = fraction.data

            f.write(header_data)
            f.write(data)

        self.fraction_paths.append(path)
        logging.debug(f"Wrote fraction #{fraction.index} to {path}")

    def write_fractions(self) -> None:
        """Convert the fraction objects to pure bytes and write them in the appropriate directory (self._out)"""
        os.makedirs(self._out_path, exist_ok=True) # enusre backup directory exists
        for fraction in self._fractions:
            self._write_fraction(fraction)

    def save_backup(self, backup_path: str):
        """Save fraction paths to a backup file."""
        try:
            with open(backup_path, "a") as f:
                for path in self.fraction_paths:
                    f.write(path + "\n")  # Ensure each path is written on a new line
            logging.debug(f"Backup saved at {backup_path}.")
        except OSError as e:
            logging.error(f"Failed to save backup: {e}")

    def load_backup(self, backup_path: str):
        """Load fraction paths from the backup file and initialize self.fraction_paths."""
        try:
            with open(backup_path, "r") as f:
                self.fraction_paths = [line.strip() for line in f]
            logging.debug(
                f"[debug: _load_backup] Loaded {len(self.fraction_paths)} paths from backup."
            )
            
        except OSError as e:
            logging.error(f"[error: _load_backup] Failed to load backup: {e}")
            return []

    def _clean_fraction(self, path: str):
        """Delete a fraction file"""
        try:
            os.remove(path)
            logging.debug(f"Removed {path}.")
        except FileNotFoundError:
            logging.debug(f"File not found: {path}")

    def clean_fractions(self) -> None:
        logging.info("Cleaning fractions . . .")
        if not self.fraction_paths:
            logging.error("No fraction paths detected.")
            return
        
        for path in self.fraction_paths:
            self._clean_fraction(path)

        self.fraction_paths = []
        logging.info("Done.")

    def do_aes_operation(self, data: bytes, op: bool) -> bytes:
        """Perform an AES-256 operation on given data (encryption [op=True]/decryption [op=False])"""
        if not self._key or not self._iv:
            raise ValueError(f"Missing key or IV (_key:{self._key}, _iv:{self._iv})")

        cipher = Cipher(algorithms.AES(self._key), modes.OFB(self._iv))
        operator = cipher.encryptor() if op else cipher.decryptor()

        return operator.update(data) + operator.finalize()

    def close_stream(self) -> None:
        """Closes the open stream to self._path and resets self._buf_rw_stream"""
        if isinstance(self._buf_reader, io.BufferedReader):
            self._buf_reader.close()
            self._buf_reader = None
            logging.debug(f"Closed stream to {self._path}.")
            return

        logging.debug(f"No stream was open.")

    @staticmethod
    def validate_aes_key(key: bytes) -> bytes:
        """Check if key is a valid AES-256 key (32 bytes)"""
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError(
                f"Invalid AES-256 key. (expected 32 bytes of `{bytes}`, got {len(key)} of `{type(key)}`)"
            )
        return key

    def __del__(self):
        self.close_stream()
