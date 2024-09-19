from dataclasses import dataclass, field
import zlib
import struct
from typing import Literal
import logging


@dataclass
class Fraction:
    """Dataclass to represent a fraction"""

    magic: int
    index: int
    iv: bytes
    data: bytes

    _crc: int = field(init=False, repr=False)
    _generated_crc: bool = field(init=False, repr=False, default=False)

    def __post_init__(self) -> None:
        """Post-initialization: calculate CRC after dataclass initialization"""
        self.calculate_crc()

    def header_to_bytes(
        self, endianess: Literal["big", "little"] = "little", include_crc=True
    ) -> bytes:
        """
        Convert the header information of the fraction to bytes.

        endianess: Endianness to use (big, little)
        include_crc: Include CRC in the returned data (default: True)
        """
        end = ">" if endianess == "big" else "<"
        fmt = f"{end}II16s{'I' if include_crc else ''}"

        # Pack the header, optionally including CRC
        args = [self.magic, self.index, self.iv]
        if include_crc:
            args.append(self.crc)

        header_data = struct.pack(fmt, *args)
        logging.debug(f"Header data [{self.index}]: {header_data.hex()}")
        return header_data

    def calculate_crc(self) -> None:
        """Calculate and store the CRC checksum of the fraction"""
        crc_data = self.header_to_bytes(include_crc=False) + self.data
        self._crc = zlib.crc32(crc_data)
        self._generated_crc = True
        logging.debug(f"Calculated CRC for fraction [{self.index}]: {self._crc:#x}")

    @property
    def crc(self) -> int:
        """Get or calculate the CRC if not already generated"""
        if not self._generated_crc:
            self.calculate_crc()
        return self._crc

    @property
    def data_size(self) -> int:
        """Return the size of the data"""
        return len(self.data)
