from dataclasses import dataclass, field
import zlib
import struct
from typing import Literal


@dataclass
class Fraction:
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
