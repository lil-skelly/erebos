import random
import string
import secrets
from typing import Optional, Type

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives._cipheralgorithm import BlockCipherAlgorithm
from cryptography.hazmat.primitives import padding

class AES_WITH_IV_HELPER:
    LENGTH_IV: int = 16

    def __init__(self, key: bytes, algorithm: Type[BlockCipherAlgorithm], mode: Type[modes.ModeWithInitializationVector]) -> None:
        self.key = key
        
        self.algorithm = algorithm(self.key)
        self.mode = mode
        
        self.padder_ctx = padding.PKCS7(self.algorithm.block_size)
        
        self._iv: Optional[bytes] = None
        
    def pad(self, data: bytes) -> bytes:
        padder = self.padder_ctx.padder()
        return padder.update(data) + padder.finalize()
    
    def unpad(self, data: bytes) -> bytes:
        unpadder = self.padder_ctx.unpadder()
        return unpadder.update(data) + unpadder.finalize()

    def get_cipher(self, iv: bytes) -> Cipher:
        """Return a cipher instance."""
        return Cipher(self.algorithm, self.mode(iv))

    def get_iv(self, new: bool = False) -> bytes:
        """Generate or reuse initialization vector (IV)."""
        if not self._iv or new:
            self._iv = secrets.token_bytes(self.LENGTH_IV)
        return self._iv

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        encryptor = self.get_cipher(self.get_iv(True)).encryptor()
        return encryptor.update(self.pad(data)) + encryptor.finalize()

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        """Decrypt data"""
        decryptor = self.get_cipher(iv).decryptor()
        return self.unpad(decryptor.update(data) + decryptor.finalize())

def random_string(n: int = 16, sample: str = string.ascii_lowercase + string.digits):
    """Returns a random string using the characters defined in sample"""
    return "".join(random.choices(sample, k=n))
