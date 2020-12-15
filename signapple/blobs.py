import io
import struct

from typing import List, Optional, Tuple

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


class SuperBlob(Blob):
    def __init__(self, magic: int):
        super().__init__(magic)
        self.entry_index: List[Tuple[int, int]] = []

    def deserialize(self, s: io.RawIOBase):
        super().deserialize(s)

        (count,) = struct.unpack(">I", sread(s, 4))
        for i in range(count):
            entry_type, offset = struct.unpack(">II", sread(s, 8))
            self.entry_index.append((entry_type, offset))
