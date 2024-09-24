import io
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from fraction import Fraction
import utils


class Fractionator(utils.AES_WITH_IV_HELPER):
    MAGIC: int = 0xDEADBEEF
    CHUNK_SIZE: int = 8192
    FRACTION_PATH_LEN: int = 16
    algorithm = algorithms.AES256
    mode = modes.CBC

    def __init__(self, file_path: str, out_path: str, key: bytes) -> None:
        """Prepare a Fractionator object for reading and generating fractions."""
        self.file_path: str = file_path
        self.file_size: int = 0
        self.out_path: str = out_path

        self._fractions: list[Fraction] = []
        self.fraction_paths: list[str] = []

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

    def _write_fraction(self, fraction: Fraction) -> None:
        """Write a fraction to a file."""
        path = os.path.join(
            self.out_path, utils.random_string(Fractionator.FRACTION_PATH_LEN)
        )
        with open(path, "wb") as f:
            f.write(fraction.header_to_bytes())
            f.write(fraction.data)
        self.fraction_paths.append(path)
        logging.debug(f"Wrote fraction #{fraction.index} to {path}")

    def write_fractions(self) -> None:
        """Write all fractions to disk."""
        os.makedirs(self.out_path, exist_ok=True)
        for fraction in self._fractions:
            self._write_fraction(fraction)

    def save_backup(self, backup_path: str) -> None:
        """Save fraction paths to a backup file."""
        try:
            with open(backup_path, "a") as f:
                f.writelines(f"{path}\n" for path in self.fraction_paths)
            logging.debug(f"Backup saved at {backup_path}.")
        except OSError as e:
            logging.error(f"Failed to save backup: {e}")

    def load_backup(self, backup_path: str) -> None:
        """Load fraction paths from a backup file."""
        try:
            with open(backup_path, "r") as f:
                self.fraction_paths = [line.strip() for line in f]
            logging.debug(f"Loaded {len(self.fraction_paths)} paths from backup.")
        except OSError as e:
            logging.error(f"Failed to load backup: {e}")
            return

    def _clean_fraction(self, path: str) -> None:
        """Delete a fraction file."""
        try:
            os.remove(path)
            logging.debug(f"Removed {path}.")
        except FileNotFoundError:
            logging.debug(f"File not found: {path}")

    def clean_fractions(self) -> None:
        """Delete all written fractions."""
        logging.info("Cleaning fractions...")
        for path in self.fraction_paths:
            self._clean_fraction(path)
        self.fraction_paths.clear()
        logging.info("Cleaning complete.")

    def close_stream(self) -> None:
        """Close the file stream if open."""
        if self._buf_reader:
            self._buf_reader.close()
            self._buf_reader = None
            logging.debug(f"Closed stream to {self.file_path}.")

    def __del__(self) -> None:
        self.close_stream()
