import plistlib
import struct

from asn1crypto.cms import ContentInfo, SignedData, CMSAttributes  # type: ignore
from asn1crypto.x509 import Certificate  # type: ignore
from collections import OrderedDict
from enum import IntEnum
from io import BytesIO, SEEK_CUR
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from .reqs import Requirement, deserialize_requirement
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


# Requirement types
HOST_REQ_TYPE = 1
GUEST_REQ_TYPE = 2
DESIGNATED_REQ_TYPE = 3
LIBRARY_REQ_TYPE = 4
PLUGIN_REQ_TYPE = 5
INVALID_REQ_TYPE = 6


class Blob(object):
    def __init__(self, magic: int):
        self.magic: int = magic
        self.length: Optional[int] = None
        self.blob_offset: int = 0

    def serialize(self, s: BinaryIO):
        pass

    def deserialize(self, s: BinaryIO):
        self.blob_offset = s.tell()
        magic, self.length = struct.unpack(">II", sread(s, 8))

        if magic != self.magic:
            raise Exception(
                f"Magic mismatch. Expected {hex(self.magic)}, got {hex(magic)}"
            )

    def seek(self, s: BinaryIO, offset):
        """
        Seek to position in s at blob_offset + offset
        """
        s.seek(self.blob_offset + offset)

    def get_hash(self, hash_type: Optional[int]) -> bytes:
        s = BytesIO()
        self.serialize(s)
        return get_hash(s.getvalue(), hash_type)


class DataBlob(Blob):
    def __init__(self, magic: int):
        super().__init__(magic)
        self.blob_data: Optional[bytes] = None

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        assert self.magic
        assert self.length
        s.seek(-8, SEEK_CUR)
        self.blob_data = sread(s, self.length)
        s.seek(8 - self.length, SEEK_CUR)

    def serialize(self, s: BinaryIO):
        assert self.blob_data
        s.write(self.blob_data)


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

        LATEST = PRE_ENCRYPT

    def __init__(self):
        super().__init__(0xFADE0C02)

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
        self.spare3: Optional[int] = None
        self.code_limit_64: Optional[int] = None
        self.exec_seg_base: Optional[int] = None
        self.exec_seg_limit: Optional[int] = None
        self.exec_seg_flags: Optional[int] = None
        self.runtime: Optional[int] = None
        self.pre_encrypt_offset: Optional[int] = None

    def get_length_offsets(self) -> Tuple[int, Dict[str, int]]:
        offsets = {}
        length = 44
        if self.version >= self.CDVersion.SCATTER:
            length += 4
        if self.version >= self.CDVersion.TEAM_ID:
            length += 4
        if self.version >= self.CDVersion.CODE_LIMIT_64:
            length += 12
        if self.version >= self.CDVersion.EXEC_SEG:
            length += 24
        if self.version >= self.CDVersion.PRE_ENCRYPT:
            length += 8

        ident_offset = length
        assert self.ident_offset is None or self.ident_offset == ident_offset
        offsets["ident"] = ident_offset

        assert self.ident
        length += len(self.ident) + 1

        if self.version >= self.CDVersion.TEAM_ID:
            assert self.team_id
            team_id_offset = length
            assert self.team_id_offset == team_id_offset
            offsets["team_id"] = team_id_offset
            length += len(self.team_id) + 1

        count_special = 0
        if self.ent_der_hash:
            count_special += 7
        elif self.rep_specific_hash:
            count_special += 6
        elif self.ent_hash:
            count_special += 5
        elif self.top_dir_hash:
            count_special += 4
        elif self.res_dir_hash:
            count_special += 3
        elif self.reqs_hash:
            count_special += 2
        elif self.info_hash:
            count_special += 1

        assert self.hash_size
        length += count_special * self.hash_size
        hash_offset = length
        assert self.hash_offset is None or self.hash_offset == hash_offset
        offsets["hash"] = hash_offset

        length += len(self.code_hashes) * self.hash_size

        return length, offsets

    def serialize(self, s: BinaryIO):
        length, offsets = self.get_length_offsets()
        assert self.length is None or length == self.length

        special_slots = [
            self.info_hash,
            self.reqs_hash,
            self.res_dir_hash,
            self.top_dir_hash,
            self.ent_hash,
            self.rep_specific_hash,
            self.ent_der_hash,
        ]
        if self.ent_der_hash:
            special_slots = special_slots[:7]
        elif self.rep_specific_hash:
            special_slots = special_slots[:6]
        elif self.ent_hash:
            special_slots = special_slots[:5]
        elif self.top_dir_hash:
            special_slots = special_slots[:4]
        elif self.res_dir_hash:
            special_slots = special_slots[:3]
        elif self.reqs_hash:
            special_slots = special_slots[:2]
        elif self.info_hash:
            special_slots = special_slots[:1]

        assert self.count_special is None or self.count_special == len(special_slots)

        s.write(
            struct.pack(
                ">9I4BI",
                self.magic,
                length,
                self.version,
                self.flags,
                offsets["hash"],
                offsets["ident"],
                len(special_slots),
                len(self.code_hashes),
                self.code_limit,
                self.hash_size,
                self.hash_type,
                self.platform,
                self.page_size,
                self.spare2,
            )
        )

        if self.version >= self.CDVersion.SCATTER:
            s.write(struct.pack(">I", self.scatter_offset))
        if self.version >= self.CDVersion.TEAM_ID:
            s.write(struct.pack(">I", offsets["team_id"]))
        if self.version >= self.CDVersion.CODE_LIMIT_64:
            s.write(struct.pack(">IQ", self.spare3, self.code_limit_64))
        if self.version >= self.CDVersion.EXEC_SEG:
            s.write(
                struct.pack(
                    ">3Q", self.exec_seg_base, self.exec_seg_limit, self.exec_seg_flags
                )
            )
        if self.version >= self.CDVersion.PRE_ENCRYPT:
            s.write(struct.pack(">2I", self.runtime, self.pre_encrypt_offset))

        assert self.ident
        s.write(self.ident)
        s.write(b"\x00")

        if self.version >= self.CDVersion.TEAM_ID:
            assert self.team_id
            s.write(self.team_id)
            s.write(b"\x00")

        assert self.hash_size
        zero_hash = b"\x00" * self.hash_size
        for h in reversed(special_slots):
            if h is None:
                s.write(zero_hash)
            else:
                s.write(h)
        for h in self.code_hashes:
            s.write(h)

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        assert self.magic is not None
        assert self.length is not None

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
            self.spare3, self.code_limit_64 = struct.unpack(">IQ", sread(s, 12))
        if self.version >= self.CDVersion.EXEC_SEG:
            (
                self.exec_seg_base,
                self.exec_seg_limit,
                self.exec_seg_flags,
            ) = struct.unpack(">3Q", sread(s, 24))
        if self.version >= self.CDVersion.PRE_ENCRYPT:
            self.runtime, self.pre_encrypt_offset = struct.unpack(">2I", sread(s, 8))

        # Because I don't know what to do with some of these fields, if we see them being used, throw an error
        # if (
        #     any(
        #         [
        #             self.scatter_offset,
        #             self.code_limit_64,
        #             self.exec_seg_base,
        #             self.exec_seg_base,
        #             self.exec_seg_limit,
        #             self.exec_seg_flags,
        #             self.runtime,
        #             self.pre_encrypt_offset,
        #         ]
        #     )
        #     is not None
        #     and any(
        #         [
        #             self.scatter_offset,
        #             self.code_limit_64,
        #             self.exec_seg_base,
        #             self.exec_seg_base,
        #             self.exec_seg_limit,
        #             self.exec_seg_flags,
        #             self.runtime,
        #             self.pre_encrypt_offset,
        #         ]
        #     )
        #     > 0
        # ):
        #     raise Exception("Unsupported feature in use")

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
        zero_hash = b"\x00" * self.hash_size
        for i in range(self.count_special):
            s.seek(-self.hash_size, SEEK_CUR)
            this_hash = sread(s, self.hash_size)
            s.seek(-self.hash_size, SEEK_CUR)

            # If the hash is the null hash (all 0's), skip
            if this_hash == zero_hash:
                continue

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
            else:
                raise Exception(f"Unknown special slot type {slot_num}")

        # ID and team ID
        self.seek(s, self.ident_offset)
        self.ident = read_string(s)
        if self.team_id_offset is not None and self.team_id_offset > 0:
            self.seek(s, self.team_id_offset)
            self.team_id = read_string(s)


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

    def serialize(self, s: BinaryIO):
        assert self.cms_data
        length = len(self.cms_data) + 8
        s.write(struct.pack(">2I", self.magic, length))
        s.write(self.cms_data)

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


class EmbeddedSignatureBlob(SuperBlob):
    def __init__(self):
        super().__init__(0xFADE0CC0)
        self.code_dir_blob: Optional[CodeDirectoryBlob] = None
        self.reqs_blob: Optional[RequirementsBlob] = None
        self.sig_blob: Optional[SignatureBlob] = None
        self.ent_blob: Optional[EntitlementsBlob] = None
        self.ent_der_blob: Optional[EntitlementsDERBlob] = None

    def serialize(self, s: BinaryIO):
        v = BytesIO()
        entry_index = []
        if self.code_dir_blob:
            entry_index.append((CODE_DIR_SLOT, v.tell()))
            self.code_dir_blob.serialize(v)
        if self.reqs_blob:
            entry_index.append((REQS_SLOT, v.tell()))
            self.reqs_blob.serialize(v)
        if self.sig_blob:
            entry_index.append((SIG_SLOT, v.tell()))
            self.sig_blob.serialize(v)
        if self.ent_blob:
            entry_index.append((ENT_SLOT, v.tell()))
            self.ent_blob.serialize(v)
        if self.ent_der_blob:
            entry_index.append((ENT_DER_SLOT, v.tell()))
            self.ent_der_blob.serialize(v)

        first_offset = 4 + 4 + 4 + 8 * len(entry_index)
        length = first_offset + v.tell()
        s.write(struct.pack(">3I", self.magic, length, len(entry_index)))
        for e, o in entry_index:
            s.write(struct.pack(">2I", e, o + first_offset))
        s.write(v.getvalue())

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
            elif entry_type == ENT_SLOT:
                self.ent_blob = EntitlementsBlob()
                self.ent_blob.deserialize(s)
            elif entry_type == ENT_DER_SLOT:
                self.ent_der_blob = EntitlementsDERBlob()
                self.ent_der_blob.deserialize(s)
            else:
                raise Exception(f"Unknown blob entry type {entry_type}")

            s.seek(orig_pos)


class RequirementBlob(Blob):
    def __init__(self, req: Optional[Requirement] = None):
        super().__init__(0xFADE0C00)
        self.kind: int = 1
        self.req: Optional[Requirement] = req

    def serialize(self, s: BinaryIO):
        assert self.req
        v = BytesIO()
        self.req.serialize(v)
        length = v.tell() + 12

        s.write(struct.pack(">3I", self.magic, length, self.kind))
        s.write(v.getvalue())

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        (kind,) = struct.unpack(">I", sread(s, 4))
        assert kind == self.kind
        self.req = deserialize_requirement(s)


class RequirementsBlob(SuperBlob):
    def __init__(self):
        super().__init__(0xFADE0C01)
        self.host_req: Optional[RequirementBlob] = None
        self.guest_req: Optional[RequirementBlob] = None
        self.designated_req: Optional[RequirementBlob] = None
        self.library_req: Optional[RequirementBlob] = None
        self.plugin_req: Optional[RequirementBlob] = None
        self.invalid_req: Optional[RequirementBlob] = None

    def serialize(self, s: BinaryIO):
        v = BytesIO()
        entry_index = []
        if self.host_req:
            entry_index.append((HOST_REQ_TYPE, v.tell()))
            self.host_req.serialize(v)
        if self.guest_req:
            entry_index.append((GUEST_REQ_TYPE, v.tell()))
            self.guest_req.serialize(v)
        if self.designated_req:
            entry_index.append((DESIGNATED_REQ_TYPE, v.tell()))
            self.designated_req.serialize(v)
        if self.library_req:
            entry_index.append((LIBRARY_REQ_TYPE, v.tell()))
            self.library_req.serialize(v)
        if self.plugin_req:
            entry_index.append((PLUGIN_REQ_TYPE, v.tell()))
            self.plugin_req.serialize(v)
        if self.invalid_req:
            entry_index.append((INVALID_REQ_TYPE, v.tell()))
            self.invalid_req.serialize(v)

        first_offset = 4 + 4 + 4 + 8 * len(entry_index)
        length = first_offset + v.tell()
        s.write(struct.pack(">3I", self.magic, length, len(entry_index)))
        for e, o in entry_index:
            s.write(struct.pack(">2I", e, o + first_offset))
        s.write(v.getvalue())

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)

        for entry_type, offset in self.entry_index:
            orig_pos = s.tell()
            self.seek(s, offset)

            req = RequirementBlob()
            req.deserialize(s)

            if entry_type == HOST_REQ_TYPE:
                self.host_req = req
            elif entry_type == GUEST_REQ_TYPE:
                self.guest_req = req
            elif entry_type == DESIGNATED_REQ_TYPE:
                self.designated_req = req
            elif entry_type == LIBRARY_REQ_TYPE:
                self.library_req = req
            elif entry_type == PLUGIN_REQ_TYPE:
                self.plugin_req = req
            elif entry_type == INVALID_REQ_TYPE:
                self.invalid_req = req
            else:
                raise Exception(f"Unknown requirement entry type {entry_type}")

            s.seek(orig_pos)


Entitlements = Dict[str, Any]


class EntitlementsBlob(Blob):
    def __init__(self, ent: Optional[Entitlements] = None):
        super().__init__(0xFADE7171)
        self.ent: Optional[Entitlements] = ent
        self.trailing_newline: bool = True

    def serialize(self, s: BinaryIO):
        assert self.ent
        v = BytesIO()
        plistlib.dump(self.ent, v, fmt=plistlib.FMT_XML, sort_keys=False)

        # Sometimes entitlements don't contain a trailing newline
        ent_data = v.getvalue()
        if not self.trailing_newline:
            ent_data = ent_data[:-1]
        length = 8 + len(ent_data)
        s.write(struct.pack(">2I", self.magic, length))
        s.write(ent_data)

    def deserialize(self, s: BinaryIO):
        super().deserialize(s)
        assert self.length
        data = sread(s, self.length - 8)
        self.trailing_newline = data[-1] == 0x0A  # Newline
        self.ent = plistlib.loads(data, fmt=plistlib.FMT_XML, dict_type=OrderedDict)


class EntitlementsDERBlob(DataBlob):
    def __init__(self):
        super().__init__(0xFADE7172)
