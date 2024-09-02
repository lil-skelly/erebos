import os
from fraction import Fraction
import io
from typing import Optional
import logging
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import utils

CHUNK_SIZE = 1024
MAGIC = 0xdeadbeef

class LKM:
    def __init__(self, path: str, out_path: str, key: bytes) -> None:
        """Class to handle loading/preparation of a LKM object file to feed to the loader"""
        self._path: str = os.path.abspath(LKM.validate_source_path(path)) # Path to LKM object file
        self._out_path: str = os.path.abspath(LKM.validate_output_path(out_path)) # Path to store generated fractions
        
        self._fractions: list[Fraction] = [] # Keep track of the fraction objects
        self._fraction_paths: list[str] = [] # Book-keeping of fraction filenames for cleanup
        # I/O
        self._buf_reader: Optional[io.BufferedReader] = None
        # AES-256 related instance attributes
        self._iv: Optional[bytes] = None # AES-256 initialization vector
        self._key: Optional[bytes] = LKM.validate_key(key) # AES-256 cryptographic key

    def open_reading_stream(self) -> None:
        """
        Opens a reading stream to the file specified in self._path.
        If a stream is already open, this function has no effect
        """
        if self._buf_reader is None or self._buf_reader.closed:
            self._buf_reader = open(self._path, "rb")
            logging.info(f"[info: load] Opened reading stream to {self._path}.")  
            return
        
        
    def _write_fraction(self, fraction: Fraction):
        """Write a fraction to a file"""
        os.makedirs(self._out_path, exist_ok=True)
        path = self._out_path + "/" + utils.random_string()
        
        with open(path, "wb") as f:
            header_data = fraction.header_to_bytes()
            data = fraction.data
            
            f.write(header_data)
            f.write(data)
                    
        self._fraction_paths.append(path)
        logging.debug(f"[debug: _write_fraction] Wrote fraction #{fraction.index} to {path}")

    def _clean_fraction(self, path: str):
        """Delete a fraction file"""
        path = LKM.validate_generic_path(path)
        os.remove(path)
        self._fraction_paths.remove(path)
        logging.debug(f"[debug] Removed {path}.")
        
    def _make_fraction(self, index: int) -> None:
        """Read from the object-file and generate a fraction"""
        if not isinstance(index, int): 
            raise ValueError(f"index must be an integer (got `{type(index)}`)")
        # Open a stream to the file and read a chunk
        self.open_reading_stream()
        data = self._buf_reader.read(CHUNK_SIZE) # don't use peek, as it does not advance the position in the file
        logging.debug("[debug: _make_fraction] Read chunk from stream.")
        
        # Generate an IV and encrypt the chunk
        self._iv = secrets.token_bytes(16) # initialization vector for AES-256 encryption
        encrypted_data = self.do_aes_operation(data, True) # encrypt chunk
        logging.info("[info: _make_fraction] Encrypted chunk data using AES-256")
        
        # Create a fraction instance and add it to self._fractions
        fraction = Fraction(
            magic=MAGIC,
            index=index,
            iv=self._iv,
            data=encrypted_data
        )
        self._fractions.append(fraction)
        print(fraction.header_to_bytes())
        logging.debug(f"[debug: _make_fraction] Created Fraction object: {fraction} (crc: {fraction.crc})")
        logging.info(f"[info: _make_fraction] Created fraction #{fraction.index}")
        
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
        if isinstance(self._buf_reader, io.BufferedReader):
            self._buf_reader.close()
            self._buf_reader = None
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