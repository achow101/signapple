#! /usr/bin/env python3

import argparse
import hashlib
import io
import macholib.MachO
import os
import struct

from asn1crypto.cms import ContentInfo, SignedData, CMSAttributes
from asn1crypto.x509 import Certificate
from io import SEEK_CUR
from macholib.mach_o import LC_CODE_SIGNATURE
from oscrypto import asymmetric
from typing import Mapping

# Primary slot numbers
# Found in both EmbeddedSignatureBlob and as negative numbers in CodeDirectory hashes array
info_slot = 1  # Info.plist
reqs_slot = 2  # Internal requirements
res_dir_slot = 3  # Resource directory
top_dir_slot = 4  # Application specific slot
ent_slot = 5  # Embedded entitlement configuration
rep_specfic_slot = 6  # For use by disk rep
ent_der_slot = 7  # DER representation of entitlements


# Virtual slot numbers
# Found only in EmbeddedSignatureBlob
code_dir_slot = 0  # CodeDirectory
alt_code_dir_slot = 0x1000  # Alternate CodeDirectory array
alt_code_dir_limit = 0x1005
sig_slot = 0x10000  # CMS Signature
id_slot = 0x10001  # Identification blob (detached signatures only)
ticket_slot = 0x10002  # Ticket embedded in signature (DMG only)


def read_string(s: io.IOBase) -> bytes:
    string = b""
    while True:
        b = s.read(1)
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


def sort_attributes(attrs_in: CMSAttributes) -> CMSAttributes:
    """
    Sort the authenticated attributes for signing by re-encoding them, asn1crypto
    takes care of the actual sorting of the set.
    """
    attrs_out = CMSAttributes()
    for attrval in attrs_in:
        attrs_out.append(attrval)
    return attrs_out


class Blob(object):
    def __init__(self, magic: int):
        self.magic: int = magic
        self.length: Optional[int] = None
        self.blob_offset: int = 0

    def deserialize(self, s: io.IOBase):
        self.blob_offset = s.tell()
        self.magic, self.length = struct.unpack(">II", s.read(8))

    def seek(self, s: io.IOBase, offset):
        """
        Seek to position in s at blob_offset + offset
        """
        s.seek(self.blob_offset + offset)


class CodeDirectoryBlob(Blob):

    earliest_version = 0x20001
    supports_scatter = 0x20100
    supports_team_id = 0x20200
    supports_code_limit_64 = 0x20300
    supports_exec_segment = 0x20400
    supports_pre_encrypt = 0x20500

    def __init__(self):
        super().__init__(0xFADE0C02)

        self.blob_data: Optional[Bytes] = None

        self.code_hashes: List[bytes] = []

        self.info_hash: Optional[bytes] = None
        self.reqs_hash: Optional[bytes] = None
        self.res_dir_hash: Optional[bytes] = None
        self.top_dir_hash: Optional[bytes] = None
        self.ent_hash: Optional[bytes] = None
        self.rep_specific_hash: Optional[bytes] = None
        self.ent_der_hash: Optional[bytes] = None

        self.ident: Optional[bytes] = None
        self.team_id: Optional[bytes] = None

        self.version: Optional[int] = None
        self.flags: Optional[int] = None
        self.hash_offset: Optional[int] = None
        self.ident_offset: Optional[int] = None
        self.count_special: Optional[int] = None
        self.count_code: Optional[int] = None
        self.code_limit: Optional[int] = None
        self.hash_size: Optional[int] = None
        self.hash_type: Optional[int] = None
        self.platform: Optional[int] = None
        self.page_size: Optional[int] = None
        self.spare2: Optional[int] = None
        self.scatter_offset: Optional[int] = None
        self.team_id_offset: Optional[int] = None
        self.code_limit_64: Optional[int] = None
        self.exec_seg_base: Optional[int] = None
        self.exec_seg_limit: Optional[int] = None
        self.exec_seg_flags: Optional[int] = None
        self.runtime: Optional[int] = None
        self.pre_encrypt_offset: Optional[int] = None

    def deserialize(self, s: io.IOBase):
        super().deserialize(s)
        s.seek(-8, SEEK_CUR)
        self.blob_data = s.read(self.length)
        s.seek(8 - self.length, SEEK_CUR)

        # Read common header
        (
            self.version,
            self.flags,
            self.hash_offset,
            self.ident_offset,
            self.count_special,
            self.count_code,
            self.code_limit,
            self.hash_size,
            self.hash_type,
            self.platform,
            self.page_size,
            self.spare2,
        ) = struct.unpack(">7I4BI", s.read(36))

        if self.version < self.earliest_version:
            raise Exception("CodeDirectory too old")

        # Read version specific fields
        if self.version >= self.supports_scatter:
            self.scatter_offset = struct.unpack(">I", s.read(4))[0]
        if self.version >= self.supports_team_id:
            self.team_id_offset = struct.unpack(">I", s.read(4))[0]
        if self.version >= self.supports_code_limit_64:
            self.code_limit_64 = struct.unpack(">Q", s.read(8))[0]
        if self.version >= self.supports_exec_segment:
            (
                self.exec_seg_base,
                self.exec_seg_limit,
                self.exec_seg_flags,
            ) = struct.unpack(">3Q", s.read(24))
        if self.version >= self.supports_pre_encrypt:
            self.runtime, self.pre_encrypt_offset = struct.unpack(">2I", s.read(16))

        # Because I don't know what to do with some of these fields, if we see them being used, throw an error
        # if (
        #    any([
        #        self.scatter_offset,
        #        self.code_limit_64,
        #        self.exec_seg_base,
        #        self.exec_seg_base,
        #        self.exec_seg_limit,
        #        self.exec_seg_flags,
        #        self.runtime,
        #        self.pre_encrypt_offset,
        #        ])
        #    is not None
        #    and any([
        #        self.scatter_offset,
        #        self.code_limit_64,
        #        self.exec_seg_base,
        #        self.exec_seg_base,
        #        self.exec_seg_limit,
        #        self.exec_seg_flags,
        #        self.runtime,
        #        self.pre_encrypt_offset,
        #        ])
        #    > 0
        # ):
        #    raise Exception("Unsupported feature in use")

        # Read code slot hashes
        self.seek(s, self.hash_offset)
        for i in range(self.count_code):
            self.code_hashes.append(s.read(self.hash_size))

        # Read special slot hashes
        # These are "negative indexes" from hash_offset
        self.special_hashes: List[bytes] = []
        self.seek(s, self.hash_offset)
        for i in range(self.count_special):
            s.seek(-self.hash_size, SEEK_CUR)
            this_hash = s.read(self.hash_size)
            s.seek(-self.hash_size, SEEK_CUR)

            slot_num = i + 1

            # Put special slot in named variable
            if slot_num == info_slot:
                self.info_hash = this_hash
            elif slot_num == reqs_slot:
                self.reqs_hash = this_hash
            elif slot_num == res_dir_slot:
                self.res_dir_hash = this_hash
            elif slot_num == top_dir_slot:
                self.top_dir_hash = this_hash
            elif slot_num == ent_slot:
                self.ent_hash = this_hash
            elif slot_num == rep_specific_slot:
                self.rep_specific_hash = this_hash
            elif slot_num == ent_der_slot:
                self.ent_der_hash = this_hash

        # ID and team ID
        self.seek(s, self.ident_offset)
        self.ident = read_string(s)
        if self.team_id_offset is not None or self.team_id_offset > 0:
            self.seek(s, self.team_id_offset)
            self.team_id = read_string(s)

    def validate(
        self, filename: str, code_limit: int, special_hashes: Mapping[int, str]
    ) -> None:
        # Code hashes
        page_size = 2 ** self.page_size
        hash_name = get_hash_name(self.hash_type)
        with open(filename, "rb") as f:
            for slot_hash in self.code_hashes:
                to_read = page_size
                if f.tell() + page_size >= code_limit:
                    to_read = code_limit - f.tell()

                h = hashlib.new(hash_name)
                h.update(f.read(to_read))
                this_hash = h.digest()
                if slot_hash != this_hash:
                    raise Exception(
                        f"Code slot hash mismatch. Expected {slot_hash.hex()}, Calculated {this_hash.hex()}"
                    )

        # CodeResources hash
        content_dir = os.path.split(os.path.split(os.path.abspath(filename))[0])[0]
        if self.res_dir_hash is not None:
            code_res_file_path = os.path.join(
                content_dir, "_CodeSignature", "CodeResources"
            )
            with open(code_res_file_path, "rb") as f:
                h = hashlib.new(hash_name)
                h.update(f.read())
                this_hash = h.digest()
                if self.res_dir_hash != this_hash:
                    raise Exception(
                        f"CodeResources Hash mismatch. Expected {self.res_dir_hash.hex()}, Calculated {this_hash.hex()}"
                    )
        # Info.plist hash
        if self.info_hash is not None:
            info_file_path = os.path.join(content_dir, "Info.plist")
            with open(info_file_path, "rb") as f:
                h = hashlib.new(hash_name)
                h.update(f.read())
                this_hash = h.digest()
                if self.info_hash != this_hash:
                    raise Exception(
                        f"Info.plist Hash mismatch. Expected {self.info_hash.hex()}, Calculated {this_hash.hex()}"
                    )
        # Requirements hash
        if self.reqs_hash is not None:
            if reqs_slot not in special_hashes:
                raise Exception("Was not able to compute a requirements hash")
            if special_hashes[reqs_slot] != self.reqs_hash:
                raise Exception(
                    f"Requirements hash mismatch. Expected {self.reqs_hash}, Calculated {special_hashes[reqs_slot]}"
                )

    def get_hash(self) -> bytes:
        hash_name = get_hash_name(self.hash_type)
        h = hashlib.new(hash_name)
        h.update(self.blob_data)
        return h.digest()


class SignatureBlob(Blob):
    """
    Blob is actually BlobWrapper with the data being a CMS signature
    """

    def __init__(self):
        super().__init__(0xFADE0B01)
        self.cms_data: Optional[bytes] = None
        self.cert_chain: List[Certificate] = []
        self.signed_attr: Optional[CMSAttributes] = None
        self.digest_alg: Optional[str] = None
        self.sig_alg: Optioanl[str] = None
        self.sig: Optiona[bytes] = None

    def deserialize(self, s: io.IOBase):
        super().deserialize(s)
        to_read = self.length - 8
        self.cms_data = s.read(to_read)

        content = ContentInfo.load(self.cms_data)
        signed_data = content["content"]
        assert isinstance(signed_data, SignedData)
        assert len(signed_data["signer_infos"]) == 1

        # Parse certificates
        for cert in signed_data["certificates"]:
            c = cert.chosen
            assert isinstance(c, Certificate)
            self.cert_chain.append(c)

        # Parse algorithms used
        signer_info = signed_data["signer_infos"][0]
        self.digest_alg = signer_info["digest_algorithm"]["algorithm"].native
        self.sig_alg = signer_info["signature_algorithm"]["algorithm"].native

        # Parse message and signature
        self.signed_attrs = signer_info["signed_attrs"]
        self.sig = signer_info["signature"].contents

    def validate(self, code_dir_hash: bytes) -> None:
        # Check the hash of CodeDirectory matches what is in the signature
        message_digest = None
        for attr in self.signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest = attr["values"][0].native
                if message_digest != code_dir_hash:
                    raise Exception(
                        "CodeDirectory Hash mismatch. Expected {message_digest}, Calculated {code_dir_hash}"
                    )
        if message_digest is None:
            raise Exception("message_digest not found in signature")

        # Check the signature
        pubkey = asymmetric.load_public_key(self.cert_chain[-1].public_key)
        signed_msg = sort_attributes(self.signed_attrs).dump()
        asymmetric.rsa_pkcs1v15_verify(pubkey, self.sig, signed_msg, self.digest_alg)


class RequirementsBlob(Blob):
    """
    We treat these blobs as black boxes. Apple's csreq tool will create these for us.
    These are SuperBlobs, but we don't really care and just need to put them in the correct
    place in an EmbeddedSignatureBlob.
    """

    def __init__(self):
        super().__init__(0xFADE0C01)
        self.blob_data: Optional[bytes] = None

    def deserialize(self, s: io.IOBase):
        super().deserialize(s)
        s.seek(-8, SEEK_CUR)
        self.blob_data = s.read(self.length)

    def get_hash(self, hash_name: str) -> bytes:
        h = hashlib.new(hash_name)
        h.update(self.blob_data)
        return h.digest()


class EmbeddedSignatureBlob(Blob):
    def __init__(self, filename: str):
        super().__init__(0xFADE0CC0)
        self.entry_index: List[Tuple[int, int]] = []
        self.code_dir_blob: Optional[CodeDirectoryBlob] = None
        self.reqs_blob: Optional[RequirementsBlob] = None
        self.sig_blob: Optional[SignatureBlob] = None

        self.filename: str = filename

        # Open the Mach-O binary and find the LC_CODE_SIGNATURE section
        m = macholib.MachO.MachO(args.filename)
        h = m.headers[0]

        sigmeta = [cmd for cmd in h.commands if cmd[0].cmd == LC_CODE_SIGNATURE]
        sigmeta = sigmeta[0]
        self.sig_offset = sigmeta[1].dataoff

    def deserialize(self, s: io.IOBase):
        super().deserialize(s)

        (count,) = struct.unpack(">I", s.read(4))
        for i in range(count):
            entry_type, offset = struct.unpack(">II", s.read(8))
            self.entry_index.append((entry_type, offset))

            # Deserialize the entries at their offsets
            orig_pos = s.tell()
            self.seek(s, offset)

            if entry_type == code_dir_slot:
                self.code_dir_blob = CodeDirectoryBlob()
                self.code_dir_blob.deserialize(s)
            elif entry_type == sig_slot:
                self.sig_blob = SignatureBlob()
                self.sig_blob.deserialize(s)
            elif entry_type == reqs_slot:
                self.reqs_blob = RequirementsBlob()
                self.reqs_blob.deserialize(s)

            s.seek(orig_pos)

    def deserialize_from_file(self):
        # Open the binary, go the signature, and parse it
        with open(args.filename, "rb") as f:
            f.seek(self.sig_offset)
            self.deserialize(f)

    def validate(self):
        special_slots = {
            reqs_slot: self.reqs_blob.get_hash(
                get_hash_name(self.code_dir_blob.hash_type)
            )
        }

        self.code_dir_blob.validate(self.filename, self.sig_offset, special_slots)
        self.sig_blob.validate(self.code_dir_blob.get_hash())


def verify(args):
    sb = EmbeddedSignatureBlob(args.filename)
    sb.deserialize_from_file()
    sb.validate()
    print("Code signature is valid")


parser = argparse.ArgumentParser(description="Signs and verifies MacOS code signatures")

subparsers = parser.add_subparsers(help="Commands")
# work-around to make subparser required
subparsers.required = True

verify_subparser = subparsers.add_parser(
    "verify", help="Verify the code signature for a binary"
)
verify_subparser.add_argument("filename", help="Path to the binary to verify")
verify_subparser.set_defaults(func=verify)

args = parser.parse_args()
args.func(args)
