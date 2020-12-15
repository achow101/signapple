import struct

from asn1crypto.cms import ContentInfo, SignedData, CMSAttributes  # type: ignore
from asn1crypto.x509 import Certificate  # type: ignore
from enum import IntEnum
from io import SEEK_CUR
from typing import BinaryIO, List, Optional, Tuple

from .utils import get_hash, sread, read_string


# Primary slot numbers
# Found in both EmbeddedSignatureBlob and as negative numbers in CodeDirectory hashes array
INFO_SLOT = 1  # Info.plist
REQS_SLOT = 2  # Internal requirements
RES_DIR_SLOT = 3  # Resource directory
TOP_DIR_SLOT = 4  # Application specific slot
ENT_SLOT = 5  # Embedded entitlement configuration
REP_SPECIFIC_SLOT = 6  # For use by disk rep
ENT_DER_SLOT = 7  # DER representation of entitlements


# Virtual slot numbers
# Found only in EmbeddedSignatureBlob
CODE_DIR_SLOT = 0  # CodeDirectory
ALT_CODE_DIR_SLOT = 0x1000  # Alternate CodeDirectory array
ALT_CODE_DIR_LIMIT = 0x1005
SIG_SLOT = 0x10000  # CMS Signature
ID_SLOT = 0x10001  # Identification blob (detached signatures only)
TICKET_SLOT = 0x10002  # Ticket embedded in signature (DMG only)


class Blob(object):
    def __init__(self, magic: int):
        self.magic: int = magic
        self.length: Optional[int] = None
        self.blob_offset: int = 0
        self.blob_data: Optional[bytes] = None

    def deserialize(self, s: BinaryIO):
        self.blob_offset = s.tell()
        magic, self.length = struct.unpack(">II", sread(s, 8))

        if magic != self.magic:
            raise Exception(
                f"Magic mismatch. Expected {hex(self.magic)}, got {hex(magic)}"
            )

        assert self.magic
        assert self.length
        s.seek(-8, SEEK_CUR)
        self.blob_data = sread(s, self.length)
        s.seek(8 - self.length, SEEK_CUR)

    def seek(self, s: BinaryIO, offset):
        """
        Seek to position in s at blob_offset + offset
        """
        s.seek(self.blob_offset + offset)

    def get_hash(self, hash_type: Optional[int]) -> bytes:
        assert self.blob_data
        return get_hash(self.blob_data, hash_type)


class SuperBlob(Blob):
    def __init__(self, magic: int):
        super().__init__(magic)
        self.entry_index: List[Tuple[int, int]] = []

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)

        (count,) = struct.unpack(">I", sread(s, 4))
        for i in range(count):
            entry_type, offset = struct.unpack(">II", sread(s, 8))
            self.entry_index.append((entry_type, offset))


class CodeDirectoryBlob(Blob):
    class CDVersion(IntEnum):
        EARLIEST = 0x20001
        SCATTER = 0x20100
        TEAM_ID = 0x20200
        CODE_LIMIT_64 = 0x20300
        EXEC_SEG = 0x20400
        PRE_ENCRYPT = 0x20500

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

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        assert self.magic is not None
        assert self.length is not None
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

        if self.version < self.CDVersion.EARLIEST:
            raise Exception("CodeDirectory too old")

        # Read version specific fields
        if self.version >= self.CDVersion.SCATTER:
            self.scatter_offset = struct.unpack(">I", sread(s, 4))[0]
        if self.version >= self.CDVersion.TEAM_ID:
            self.team_id_offset = struct.unpack(">I", sread(s, 4))[0]
        if self.version >= self.CDVersion.CODE_LIMIT_64:
            self.code_limit_64 = struct.unpack(">Q", sread(s, 8))[0]
        if self.version >= self.CDVersion.EXEC_SEG:
            (
                self.exec_seg_base,
                self.exec_seg_limit,
                self.exec_seg_flags,
            ) = struct.unpack(">3Q", sread(s, 24))
        if self.version >= self.CDVersion.PRE_ENCRYPT:
            self.runtime, self.pre_encrypt_offset = struct.unpack(">2I", sread(s, 16))

        # Because I don't know what to do with some of these fields, if we see them being used, throw an error
        if (
           any([
               self.scatter_offset,
               self.code_limit_64,
               self.exec_seg_base,
               self.exec_seg_base,
               self.exec_seg_limit,
               self.exec_seg_flags,
               self.runtime,
               self.pre_encrypt_offset,
               ])
           is not None
           and any([
               self.scatter_offset,
               self.code_limit_64,
               self.exec_seg_base,
               self.exec_seg_base,
               self.exec_seg_limit,
               self.exec_seg_flags,
               self.runtime,
               self.pre_encrypt_offset,
               ])
           > 0
        ):
           raise Exception("Unsupported feature in use")

        # Read code slot hashes
        self.seek(s, self.hash_offset)
        assert self.count_code
        assert self.hash_size
        for i in range(self.count_code):
            self.code_hashes.append(sread(s, self.hash_size))

        # Read special slot hashes
        # These are "negative indexes" from hash_offset
        self.special_hashes: List[bytes] = []
        self.seek(s, self.hash_offset)
        assert self.count_special
        for i in range(self.count_special):
            s.seek(-self.hash_size, SEEK_CUR)
            this_hash = sread(s, self.hash_size)
            s.seek(-self.hash_size, SEEK_CUR)

            slot_num = i + 1

            # Put special slot in named variable
            if slot_num == INFO_SLOT:
                self.info_hash = this_hash
            elif slot_num == REQS_SLOT:
                self.reqs_hash = this_hash
            elif slot_num == RES_DIR_SLOT:
                self.res_dir_hash = this_hash
            elif slot_num == TOP_DIR_SLOT:
                self.top_dir_hash = this_hash
            elif slot_num == ENT_SLOT:
                self.ent_hash = this_hash
            elif slot_num == REP_SPECIFIC_SLOT:
                self.rep_specific_hash = this_hash
            elif slot_num == ENT_DER_SLOT:
                self.ent_der_hash = this_hash

        # ID and team ID
        self.seek(s, self.ident_offset)
        self.ident = read_string(s)
        if self.team_id_offset is not None and self.team_id_offset > 0:
            self.seek(s, self.team_id_offset)
            self.team_id = read_string(s)

    def get_hash(self) -> bytes:
        assert self.hash_type
        assert self.blob_data
        return get_hash(self.blob_data, self.hash_type)


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

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        assert self.magic
        assert self.length
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


class RequirementsBlob(Blob):
    """
    We treat these blobs as black boxes. Apple's csreq tool will create these for us.
    These are SuperBlobs, but we don't really care and just need to put them in the correct
    place in an EmbeddedSignatureBlob.
    """

    def __init__(self):
        super().__init__(0xFADE0C01)


class EmbeddedSignatureBlob(SuperBlob):
    def __init__(self):
        super().__init__(0xFADE0CC0)
        self.code_dir_blob: Optional[CodeDirectoryBlob] = None
        self.reqs_blob: Optional[RequirementsBlob] = None
        self.sig_blob: Optional[SignatureBlob] = None

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)

        for entry_type, offset in self.entry_index:
            # Deserialize the entries at their offsets
            orig_pos = s.tell()
            self.seek(s, offset)

            if entry_type == CODE_DIR_SLOT:
                self.code_dir_blob = CodeDirectoryBlob()
                self.code_dir_blob.deserialize(s)
            elif entry_type == SIG_SLOT:
                self.sig_blob = SignatureBlob()
                self.sig_blob.deserialize(s)
            elif entry_type == REQS_SLOT:
                self.reqs_blob = RequirementsBlob()
                self.reqs_blob.deserialize(s)

            s.seek(orig_pos)
