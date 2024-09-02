import struct
import random
import string

def swap32(i: int):
    """Swap the endianess of a 32-bit integer"""
    return struct.unpack("<I", struct.pack(">I", i))[0]

def random_string(n: int = 16, sample: str = string.ascii_lowercase+string.digits):
    """Returns a random string using the characters defined in sample"""
    return "".join(random.choices(sample, k=n))