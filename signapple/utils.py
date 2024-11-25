import glob
import hashlib
import plistlib
import os

from elfesteem.macho import MACHO
from typing import BinaryIO, Optional, Tuple


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


def hash_file(filename: str, hash_type: Optional[int]) -> bytes:
    with open(filename, "rb") as f:
        return get_hash(f.read(), hash_type)


def round_up(n: int, i: int) -> int:
    if n % i == 0:
        return n
    return ((n // i) + 1) * i


def get_bundle_exec(filepath: str) -> Tuple[Optional[str], str]:
    """
    Get the path to the bundle dir (contains the Contents dir) and the (main) executable itself.
    filepath may be the path to an exec, or to the bundle dir. If to the bundle dir, the main
    executable as specified in the Info.plist is returned.
    """
    filepath = os.path.abspath(filepath)
    if os.path.isfile(filepath):
        # This is a file, we should check it is a Mach-O. elfesteem can do this for us
        # It will raise if it is not
        with open(filepath, "rb") as f:
            macho = MACHO(f.read(), parseSymbols=False)

        # Figure out the bundle path
        macos_dir = os.path.dirname(filepath)
        if os.path.basename(macos_dir) != "MacOS":
            # Not in a bundle, return just the binary path
            return None, filepath
        content_dir = os.path.dirname(macos_dir)
        if os.path.basename(content_dir) != "Contents":
            # If we got here, then there appears to be a bundle but it's not correctly laid out
            raise Exception(
                "File is not in a correctly formatted Bundle. Missing Contents dir"
            )
        bundle_dir = os.path.dirname(content_dir)
        return bundle_dir, filepath
    elif os.path.isdir(filepath):
        # This is a directory. Check it is a bundle and find the binary
        content_dir = os.path.join(filepath, "Contents")
        if not os.path.isdir(content_dir):
            raise Exception(
                "Path is not a correctly formatted Bundle. Missing Contents dir"
            )
        macos_dir = os.path.join(content_dir, "MacOS")
        if not os.path.isdir(macos_dir):
            raise Exception(
                "Path is not a correctly formatted Bundle. Missing MacOS dir"
            )

        info_file_path = os.path.join(content_dir, "Info.plist")
        with open(info_file_path, "rb") as f:
            info = plistlib.load(f)
            main_exec_name = info["CFBundleExecutable"]

        # List all file in this directory
        files = glob.glob(os.path.join(macos_dir, "*"))
        if len(files) == 0:
            raise Exception("No binary to sign")
        for filename in files:
            if os.path.basename(filename) == main_exec_name:
                return filepath, filename
        raise Exception("Bundle does not contain main exectuable")
    else:
        raise Exception("Path is not a bundle directory or a file")


def get_macho_list(m: MACHO):
    if hasattr(m, "Fhdr"):
        return m.arch
    else:
        return [m]


def hash_name(hash_type: int) -> str:
    """
    Get the name of the hash function from the integer type
    """
    if hash_type == 1:
        return "sha1"
    elif hash_type == 2:
        return "sha256"
    raise Exception("Unknown hash type")


def hash_code_res_name(hash_type: int) -> str:
    """
    Get the name of the hash for use in CodeResources
    """
    if hash_type == 1:  # SHA1 is just called "hash"
        return "hash"
    return f"hash{hash_type}"  # The rest is called "hashn" where n is the type value
