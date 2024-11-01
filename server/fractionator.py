import io
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers import algorithms, modes
from fraction import Fraction
import utils

import zlib


class Fractionator(utils.AES_WITH_IV_HELPER):
    MAGIC: int = 0xDEADBEEF
    CHUNK_SIZE: int = 8192
    FRACTION_PATH_LEN: int = 16
    algorithm = algorithms.AES256
    mode = modes.CBC

    def __init__(self, key: bytes) -> None:
        """Prepare a Fractionator object for reading and generating fractions."""
        self.file_path: str = NotImplemented
        self.file_size: int = 0

        self._fractions: list[Fraction] = []
        self.fractions: list[bytes] = []

        self._buf_reader: Optional[io.BufferedReader] = None

        super().__init__(key, self.algorithm, self.mode)

    def open_reading_stream(self) -> None:
        """Open a stream for reading the object file."""
        if not self._buf_reader or self._buf_reader.closed:
            try:
                self._buf_reader = open(self.file_path, "rb")
                logging.debug(f"Opened stream to {self.file_path}.")
            except FileNotFoundError as err:
                logging.error(f"File not found: {self.file_path}")
                raise err

    def _make_fraction(self, index: int) -> None:
        """Generate and encrypt a fraction from the object file."""
        self.open_reading_stream()

        data = self._buf_reader.read(self.CHUNK_SIZE)
        encrypted_data = self.encrypt(data)

        fraction = Fraction(
            magic=self.MAGIC, index=index, iv=self.get_iv(), data=encrypted_data
        )
        self._fractions.append(fraction)

        logging.debug(f"Created fraction #{fraction.index}")

    def make_fractions(self) -> None:
        """Generate all fractions from the object file."""
        self.file_size = (
            os.path.getsize(self.file_path) if not self.file_size else self.file_size
        )

        num_chunks = (self.file_size + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        logging.info(f"Creating {num_chunks} fractions.")
        for i in range(num_chunks):
            self._make_fraction(i)

    def write_fractions(self) -> None:
        """Write all fractions to disk."""
        for fraction in self._fractions:
            fraction_data = fraction.header_to_bytes() + fraction.data
            self.fractions.append(fraction_data)

    def close_stream(self) -> None:
        """Close the file stream if open."""
        if self._buf_reader:
            self._buf_reader.close()
            self._buf_reader = None
            logging.debug(f"Closed stream to {self.file_path}.")

    def finalize(self) -> None:
        """Create, write and save a backup of the fractions"""
        self.make_fractions()
        self.write_fractions()

    def __del__(self) -> None:
        self.close_stream()
