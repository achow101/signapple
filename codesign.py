#! /usr/bin/env python3

import argparse
import io
import struct


# Primary slot numbers
# Found in both SuperBlob and as negative numbers in CodeDirectory hashes array
info_slot = 1  # Info.plist
reqs_slot = 2  # Internal requirements
res_dir_slot = 3  # Resource directory
top_dir_slot = 4  # Application specific slot
ent_slot = 5  # Embedded entitlement configuration
rep_specfic_slot = 6  # For use by disk rep
ent_der_slot = 7  # DER representation of entitlements


# Virtual slot numbers
# Found only in SuperBlob
code_dir_slot = 0  # CodeDirectory
alt_code_dir_slot = 0x1000  # Alternate CodeDirectory array
alt_code_dir_limit = 0x1005
sig_slot = 0x10000  # CMS Signature
id_slot = 0x10001  # Identification blob (detached signatures only)
ticket_slot = 0x10002  # Ticket embedded in signature (DMG only)


parser = argparse.ArgumentParser(description="Signs and verifies MacOS code signatures")

subparsers = parser.add_subparsers(help="Commands")

verify_subparser = subparsers.add_subparser(
    "verify", help="Verify the code signature for a binary"
)
verify_subparser.add_argument("filename", help="Path to the binary to verify")

args = parser.parse_args()


class Blob(object):
    def __init__(self, magic: int):
        self.magic: int = magic
        self.length: Optional[int] = None

    def deserialize(self, s: io.IOBase):
        self.magic, self.length = struct.unpack(">II", s.read(8))


class SuperBlob(Blob):
    def __init__(self, entries: List[Tuple[int, int]]):
        super().__init__(0xFADE0CC0)
        self.entry_index: List[Tuple[int, int]] = entries

    def deserialize(self, s: io.IOBase):
        super.deserialize(s)

        count = struct.unpack(">I", s.read(4))
        for i in range(count):
            entry_type, offset = struct.unpack(">II", s.read(8))
            self.entry_index.append((entry_type, offset))

            # Deserialize the entries at their offsets
            orig_pos = s.tell()
            s.seek(offset)

            if entry_type == code_dir_slot:
                pass
            elif entry_type == sig_slot:
                pass
            elif entry_type == reqs_slot:
                pass
