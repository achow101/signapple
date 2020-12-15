from typing import BinaryIO


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


def get_hash_name(t: int) -> str:
    if t == 1:
        return "sha1"
    elif t == 2 or t == 3:
        return "sha256"
    elif t == 4:
        return "sha384"
    elif t == 5:
        return "sha512"
    raise Exception("No or unknown hash type")
