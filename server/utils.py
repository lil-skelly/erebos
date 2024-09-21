import random
import string
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, modes


class AES_CFB_HELPER:
    LENGTH_IV: int = 16

    def __init__(self, key: bytes, algorithm) -> None:
        self.algorithm = algorithm
        self.mode = modes.CFB
        self.key: bytes = key
        self._iv: Optional[bytes] = None

    def get_cipher(self, iv: bytes) -> Cipher:
        """Return a cipher instance."""
        return Cipher(self.algorithm(self.key), self.mode(iv))

    def get_iv(self, new: bool = False) -> bytes:
        """Generate or reuse initialization vector (IV)."""
        if not self._iv or new:
            return secrets.token_bytes(self.LENGTH_IV)
        return self._iv

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-CFB mode."""
        cipher = self.get_cipher(self.get_iv(True))
        operator = cipher.encryptor()
        return operator.update(data) + operator.finalize()


def random_string(n: int = 16, sample: str = string.ascii_lowercase + string.digits):
    """Returns a random string using the characters defined in sample"""
    return "".join(random.choices(sample, k=n))
