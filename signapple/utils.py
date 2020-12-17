import hashlib

from typing import BinaryIO, Optional


def sread(s: BinaryIO, n: int) -> bytes:
    b = s.read(n)
    if b is None:
        b = b""
    return b


def read_string(s: BinaryIO) -> bytes:
    string = b""
    while True:
        b = sread(s, 1)
        if b == b"\x00":
            break
        string += b
    return string


def get_hash(data: bytes, hash_type: Optional[int]) -> bytes:
    if hash_type == 1:
        hash_name = "sha1"
    elif hash_type == 2 or hash_type == 3:
        hash_name = "sha256"
    elif hash_type == 4:
        hash_name = "sha384"
    elif hash_type == 5:
        hash_name = "sha512"
    else:
        raise Exception("No or unknown hash type")

    h = hashlib.new(hash_name)
    h.update(data)
    r = h.digest()

    if hash_type == 3:
        # This is a sha256 hash truncated to 20 bytes
        return r[:20]
    return r


def print_hex(data: bytes):
    for i in range(0, len(data), 4):
        print(f"{data[i:i+2].hex()} {data[i+2:i+4].hex()}")
