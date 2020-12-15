import io


def sread(s: io.RawIOBase, n: int) -> bytes:
    b = s.read(n)
    if b is None:
        b = b""
    return b


def read_string(s: io.RawIOBase) -> bytes:
    string = b""
    while True:
        b = sread(s, 1)
        if b == b"\x00":
            break
        string += b
    return string
