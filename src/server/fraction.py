from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import struct
import zlib
from typing import Literal, Optional

@dataclass
class Fraction:
    """
    Dataclass representing the header of a fraction.
    """
    magic: int
    index: int
    iv: bytes
    crc: int = field(init=False, repr=True, default=0)
    data: bytes = field(repr=False)
        
    def calculate_crc(self) -> None:
        """Lazy calculation of the headers CRC-32 checksum"""
        if self.crc == 0:
            crc_data = self.header_to_bytes(crc=False) + self.data
            self.crc = zlib.crc32(crc_data)
        
    def header_to_bytes(
        self,
        endianess: Literal["big", "little"] = "big",
        crc: bool = True # include CRC
    ) -> bytes:
        """Return the header information packed to bytes"""
        end = ">" if endianess=="big" else "<" # handle endianess
        fmt = f"{end}II16sI" if crc else f"{end}II16s" # handle fmt
        args = [fmt, self.magic, self.index, self.iv] # struct.pack arguments
        if crc: args.append(self.crc)
        
        return struct.pack(*args)

    def __post_init__(self): 
        self.calculate_crc()