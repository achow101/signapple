#! /usr/bin/env python3

import argparse
import hashlib
import io
import macholib.MachO # type: ignore
import os
import struct

from asn1crypto.cms import ContentInfo, SignedData, CMSAttributes # type: ignore
from asn1crypto.x509 import Certificate # type: ignore
from certvalidator.context import ValidationContext # type: ignore
from certvalidator import CertificateValidator # type: ignore
from io import SEEK_CUR
from macholib.mach_o import LC_CODE_SIGNATURE # type: ignore
from oscrypto import asymmetric # type: ignore
from typing import List, Mapping, Optional, Tuple

# Primary slot numbers
# Found in both EmbeddedSignatureBlob and as negative numbers in CodeDirectory hashes array
info_slot = 1  # Info.plist
reqs_slot = 2  # Internal requirements
res_dir_slot = 3  # Resource directory
top_dir_slot = 4  # Application specific slot
ent_slot = 5  # Embedded entitlement configuration
rep_specific_slot = 6  # For use by disk rep
ent_der_slot = 7  # DER representation of entitlements


# Virtual slot numbers
# Found only in EmbeddedSignatureBlob
code_dir_slot = 0  # CodeDirectory
alt_code_dir_slot = 0x1000  # Alternate CodeDirectory array
alt_code_dir_limit = 0x1005
sig_slot = 0x10000  # CMS Signature
id_slot = 0x10001  # Identification blob (detached signatures only)
ticket_slot = 0x10002  # Ticket embedded in signature (DMG only)

APPLE_ROOT_CERT = b'0\x82\x04\xbb0\x82\x03\xa3\xa0\x03\x02\x01\x02\x02\x01\x020\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000b1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nApple Inc.1&0$\x06\x03U\x04\x0b\x13\x1dApple Certification Authority1\x160\x14\x06\x03U\x04\x03\x13\rApple Root CA0\x1e\x17\r060425214036Z\x17\r350209214036Z0b1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nApple Inc.1&0$\x06\x03U\x04\x0b\x13\x1dApple Certification Authority1\x160\x14\x06\x03U\x04\x03\x13\rApple Root CA0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xe4\x91\xa9\t\x1f\x91\xdb\x1eGP\xeb\x05\xed^y\x84-\xeb6\xa2WLU\xec\x8b\x19\x89\xde\xf9Kl\xf5\x07\xab"0\x02\xe8\x18>\xf8P\t\xd3\x7fA\xa8\x98\xf9\xd1\xcaf\x9c$k\x11\xd0\xa3\xbb\xe4\x1b*\xc3\x1f\x95\x9ez\x0c\xa4G\x8b[\xd4\x1673\xcb\xc4\x0fM\xce\x14i\xd1\xc9\x19r\xf5]\x0e\xd5\x7f_\x9b\xf2%\x03\xbaU\x8fM]\r\xf1d5#\x15K\x15Y\x1d\xb3\x94\xf7\xf6\x9c\x9e\xcfP\xba\xc1XPg\x8f\x08\xb4 \xf7\xcb\xac, op\xb6?\x010\x8c\xb7C\xcf\x0f\x9d=\xf3+I(\x1a\xc8\xfe\xce\xb5\xb9\x0e\xd9^\x1c\xd6\xcb=\xb5:\xad\xf4\x0f\x0e\x00\x92\x0b\xb1!\x16.t\xd5<\r\xdbb\x16\xab\xa3q\x92GSU\xc1\xaf/A\xb3\xf8\xfb\xe3p\xcd\xe6\xa3LE~\x1fLkP\x96A\x89\xc4tb\x0b\x10\x83A\x873\x8a\x81\xb10X\xecZ\x042\x8ch\xb3\x8f\x1d\xdees\xffg^e\xbcI\xd8v\x9f3\x14e\xa1w\x94\xc9-\x02\x03\x01\x00\x01\xa3\x82\x01z0\x82\x01v0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x060\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14+\xd0iG\x94v\t\xfe\xf4k\x8d.@\xa6\xf7GM\x7f\x08^0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14+\xd0iG\x94v\t\xfe\xf4k\x8d.@\xa6\xf7GM\x7f\x08^0\x82\x01\x11\x06\x03U\x1d \x04\x82\x01\x080\x82\x01\x040\x82\x01\x00\x06\t*\x86H\x86\xf7cd\x05\x010\x81\xf20*\x06\x08+\x06\x01\x05\x05\x07\x02\x01\x16\x1ehttps://www.apple.com/appleca/0\x81\xc3\x06\x08+\x06\x01\x05\x05\x07\x02\x020\x81\xb6\x1a\x81\xb3Reliance on this certificate by any party assumes acceptance of the then applicable standard terms and conditions of use, certificate policy and certification practice statements.0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\\6\x99L-x\xb7\xed\x8c\x9b\xdc\xf3w\x9b\xf2v\xd2w0O\xc1\x1f\x85\x83\x85\x1b\x99=G7\xf2\xa9\x9b@\x8e,\xd4\xb1\x90\x12\xd8\xbe\xf4s\x9b\xee\xd2d\x0f\xcbyO4\xd8\xa2>\xf9x\xffk\xc8\x07\xec}9\x83\x8bS \xd38\xc4\xb1\xbf\x9aO\nk\xff+\xfcY\xa7\x05\t|\x17@V\x11\x1et\xd3\xb7\x8b#;G\xa3\xd5o$\xe2\xeb\xd1\xb7p\xdf\x0fE\xe1\'\xca\xf1mx\xed\xe7\xb5\x17\x17\xa8\xdc~"5\xca%\xd5\xd9\x0f\xd6k\xd4\xa2$#\x11\xf7\xa1\xac\x8fs\x81`\xc6\x1b[\t/\x92\xb2\xf8DH\xf0`8\x9e\x15\xf5=&g \x8a3j\xf7\r\x82\xcf\xde\xeb\xa3/\xf9Sj[d\xc0c3w\xf7:\x07,V\xeb\xda\x0f!\x0e\xda\xbas\x19O\xb5\xd96\x7f\xc1\x87U\xd9\xa7\x99\xb92B\xfb\xd8\xd5q\x9e~\xa1R\xb7\x1b\xbd\x93B$\x12*\xc7\x0f\x1d\xb6M\x9c^c\xc8K\x80\x17P\xaa\x8a\xd5\xda\xe4\xfc\xd0\t\x077\xb0uu!'


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

        self.version: int = 0
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

    def deserialize(self, s: io.RawIOBase):
        super().deserialize(s)
        assert(self.magic is not None)
        assert(self.length is not None)
        s.seek(-8, SEEK_CUR)
        self.blob_data = sread(s, self.length)
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
        ) = struct.unpack(">7I4BI", sread(s, 36))

        if self.version < self.earliest_version:
            raise Exception("CodeDirectory too old")

        # Read version specific fields
        if self.version >= self.supports_scatter:
            self.scatter_offset = struct.unpack(">I", sread(s, 4))[0]
        if self.version >= self.supports_team_id:
            self.team_id_offset = struct.unpack(">I", sread(s, 4))[0]
        if self.version >= self.supports_code_limit_64:
            self.code_limit_64 = struct.unpack(">Q", sread(s, 8))[0]
        if self.version >= self.supports_exec_segment:
            (
                self.exec_seg_base,
                self.exec_seg_limit,
                self.exec_seg_flags,
            ) = struct.unpack(">3Q", sread(s, 24))
        if self.version >= self.supports_pre_encrypt:
            self.runtime, self.pre_encrypt_offset = struct.unpack(">2I", sread(s, 16))

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
        assert(self.count_code)
        assert(self.hash_size)
        for i in range(self.count_code):
            self.code_hashes.append(sread(s, self.hash_size))

        # Read special slot hashes
        # These are "negative indexes" from hash_offset
        self.special_hashes: List[bytes] = []
        self.seek(s, self.hash_offset)
        assert(self.count_special)
        for i in range(self.count_special):
            s.seek(-self.hash_size, SEEK_CUR)
            this_hash = sread(s, self.hash_size)
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
        if self.team_id_offset is not None and self.team_id_offset > 0:
            self.seek(s, self.team_id_offset)
            self.team_id = read_string(s)

    def validate(self, filename: str, special_hashes: Mapping[int, bytes]) -> None:
        # Code hashes
        assert(self.page_size)
        assert(self.hash_type)
        assert(self.code_limit)
        page_size = 2 ** self.page_size
        hash_name = get_hash_name(self.hash_type)
        with open(filename, "rb") as f:
            for slot_hash in self.code_hashes:
                to_read = page_size
                if f.tell() + page_size >= self.code_limit:
                    to_read = self.code_limit - f.tell()

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
                    f"Requirements hash mismatch. Expected {self.reqs_hash.hex()}, Calculated {special_hashes[reqs_slot].hex()}"
                )

    def get_hash(self) -> bytes:
        assert(self.hash_type)
        assert(self.blob_data)
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

    def deserialize(self, s: io.RawIOBase):
        super().deserialize(s)
        assert(self.magic)
        assert(self.length)
        to_read = self.length - 8
        self.cms_data = sread(s, to_read)

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

        # Validate the certificate chain
        validation_context = ValidationContext(
            trust_roots=[APPLE_ROOT_CERT],
            allow_fetching=False,
            additional_critical_extensions=set(["1.2.840.113635.100.6.1.13"]),
        )
        validator = CertificateValidator(
            self.cert_chain[-1], self.cert_chain[0:-1], validation_context
        )
        validator.validate_usage({"digital_signature"}, {"code_signing"})

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

    def deserialize(self, s: io.RawIOBase):
        super().deserialize(s)
        assert(self.magic)
        assert(self.length)
        s.seek(-8, SEEK_CUR)
        self.blob_data = sread(s, self.length)

    def get_hash(self, hash_name: str) -> bytes:
        assert(self.blob_data)
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

    def deserialize(self, s: io.RawIOBase):
        super().deserialize(s)

        (count,) = struct.unpack(">I", sread(s, 4))
        for i in range(count):
            entry_type, offset = struct.unpack(">II", sread(s, 8))
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

        self.code_dir_blob.validate(self.filename, special_slots)
        self.sig_blob.validate(self.code_dir_blob.get_hash())


def verify(args):
    sb = EmbeddedSignatureBlob(args.filename)
    sb.deserialize_from_file()
    sb.validate()
    print("Code signature is valid")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Signs and verifies MacOS code signatures"
    )

    subparsers = parser.add_subparsers(help="Commands", dest="command", required=True)

    verify_subparser = subparsers.add_parser(
        "verify", help="Verify the code signature for a binary"
    )
    verify_subparser.add_argument("filename", help="Path to the binary to verify")
    verify_subparser.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)
