import io
import struct

from typing import Optional

from .utils import sread


class Blob(object):
    def __init__(self, magic: int):
        self.magic: int = magic
        self.length: Optional[int] = None
        self.blob_offset: int = 0

    def deserialize(self, s: io.RawIOBase):
        self.blob_offset = s.tell()
        magic, self.length = struct.unpack(">II", sread(s, 8))

        if magic != self.magic:
            raise Exception(
                "Magic mismatch. Expected {hex(self.magic)}}, got {hex(magic)}"
            )

    def seek(self, s: io.RawIOBase, offset):
        """
        Seek to position in s at blob_offset + offset
        """
        s.seek(self.blob_offset + offset)
