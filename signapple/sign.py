import getpass
import glob
import os
import plistlib
import shutil
import subprocess
import re
import requests

from asn1crypto.algos import DigestAlgorithmId, SignedDigestAlgorithmId
from asn1crypto.core import ObjectIdentifier, OctetString, Sequence, SetOf, UTCTime
from asn1crypto.cms import (
    CMSAttribute,
    CMSAttributes,
    CMSAttributeType,
    CMSVersion,
    ContentInfo,
    ContentType,
    DigestAlgorithm,
    IssuerAndSerialNumber,
    SetOfAny,
    SignedData,
    SignedDigestAlgorithm,
    SignerIdentifier,
    SignerInfo,
)
from asn1crypto.tsp import MessageImprint, TimeStampReq, TimeStampResp, Version
from asn1crypto.x509 import Certificate
from asn1crypto.keys import PrivateKeyInfo
from collections import OrderedDict
from datetime import datetime, timezone
from elfesteem.macho import (
    CodeSignature,
    LC_BUILD_VERSION,
    LC_CODE_SIGNATURE,
    linkedit_data_command,
    MACHO,
    segment_command,
)
from elfesteem.strpatchwork import StrPatchwork
from io import BytesIO
from math import log2
from oscrypto.asymmetric import load_private_key, rsa_pkcs1v15_sign
from oscrypto.keys import parse_pkcs12, parse_private
from typing import Any, Dict, List, Optional, Tuple

from .blobs import (
    EmbeddedSignatureBlob,
    EntitlementsBlob,
    CodeDirectoryBlob,
    RequirementsBlob,
    RequirementBlob,
    SignatureBlob,
)
from .certs import APPLE_INTERMEDIATES, APPLE_ROOTS
from .reqs import (
    AndOrExpr,
    ArgMatchExpr,
    CertificateMatch,
    ExprOp,
    Expr,
    MatchOP,
    Requirement,
    SingleArgExpr,
)
from .utils import get_bundle_exec, get_hash, get_macho_list, hash_file, round_up


HASH_AGILITY_V1_OID = CMSAttributeType("1.2.840.113635.100.9.1")
HASH_AGILITY_V2_OID = CMSAttributeType("1.2.840.113635.100.9.2")

PAGE_SIZES = {
    0x01000007: 0x1000,  # AMD64
    0x0100000C: 0x4000,  # ARM64
}

CPU_NAMES = {
    0x01000007: "x86_64",  # AMD64
    0x0100000C: "arm64",  # ARM64
}

CPU_NAME_TO_TYPE = {
    "x86_64": 0x01000007,  # AMD64
    "arm64": 0x0100000C,  # ARM64
}

# Lookup table for the Log2 page size that is put in the CodeDirectory
CODE_DIR_PAGE_SIZES = {
    0x1000: 12,
    0x4000: 14,
}


TIMESTAMP_SERVER = "http://timestamp.apple.com/ts01"


class HashAgility(Sequence):
    _fields = [("type", ObjectIdentifier), ("data", OctetString)]


def make_hash_agility_v1(digest: bytes) -> CMSAttribute:
    """
    CMSAttribue:
        type: HASH_AGILITY_V1_OID
        values: Set of 1 XML Plist
            dict: {
                "cdhashes": [digset truncated to 20 bytes]
            }
    """
    plist_dict = {"cdhashes": [digest[:20]]}
    plist_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
    return CMSAttribute(
        {"type": HASH_AGILITY_V1_OID, "values": [OctetString(plist_bytes)]}
    )


def _get_digest_algo(hash_type: int) -> DigestAlgorithmId:
    dg_algo = None
    if hash_type == 1:
        dg_algo = DigestAlgorithmId.unmap("sha1")
    elif hash_type == 2 or hash_type == 3:
        dg_algo = DigestAlgorithmId.unmap("sha256")
    elif hash_type == 4:
        dg_algo = DigestAlgorithmId.unmap("sha384")
    elif hash_type == 5:
        dg_algo = DigestAlgorithmId.unmap("sha512")
    assert dg_algo
    return dg_algo


def make_hash_agility_v2(digest: bytes, hash_type: int) -> CMSAttribute:
    """
    CMSAttribute:
        type: HASH_AGILITY_V2_OID
        values: Set of HashAgility
            type: DigestAlgorithmId
            data: digest
    """
    dg_algo = _get_digest_algo(hash_type)
    ha = HashAgility({"type": dg_algo, "data": OctetString(digest)})
    return CMSAttribute({"type": HASH_AGILITY_V2_OID, "values": [ha]})


def make_signed_attrs(digest: bytes, hash_type: int) -> CMSAttributes:
    content_type = CMSAttribute(
        {
            "type": CMSAttributeType.unmap("content_type"),
            "values": [ContentType.unmap("data")],
        }
    )

    time_now = UTCTime()
    time_now.set(datetime.now(timezone.utc))
    signing_time = CMSAttribute(
        {"type": CMSAttributeType.unmap("signing_time"), "values": [time_now]}
    )

    message_digest = CMSAttribute(
        {
            "type": CMSAttributeType.unmap("message_digest"),
            "values": [OctetString(digest)],
        }
    )

    ha_v1 = make_hash_agility_v1(digest)

    ha_v2 = make_hash_agility_v2(digest, hash_type)

    return CMSAttributes([content_type, signing_time, message_digest, ha_v1, ha_v2])


def make_certificate_chain(cert):
    certs = [cert]
    for c in APPLE_INTERMEDIATES:
        if (
            certs[-1].native["tbs_certificate"]["issuer"]
            == c.native["tbs_certificate"]["subject"]
        ):
            certs.append(c)
            break
    for c in APPLE_ROOTS:
        if (
            certs[-1].native["tbs_certificate"]["issuer"]
            == c.native["tbs_certificate"]["subject"]
        ):
            certs.append(c)
            break
    return list(reversed(certs))


def make_cms(
    cert: Certificate,
    hash_type: int,
    signed_attrs: CMSAttributes,
    sig: bytes,
    unsigned_attrs: Optional[CMSAttributes],
) -> ContentInfo:
    sid = SignerIdentifier(
        "issuer_and_serial_number",
        IssuerAndSerialNumber(
            {
                "issuer": cert["tbs_certificate"]["issuer"],
                "serial_number": cert["tbs_certificate"]["serial_number"],
            }
        ),
    )

    dg_algo = DigestAlgorithm({"algorithm": _get_digest_algo(hash_type)})

    sig_algo = SignedDigestAlgorithm(
        {"algorithm": SignedDigestAlgorithmId("rsassa_pkcs1v15")}
    )

    sig_info = SignerInfo(
        {
            "version": CMSVersion(1),
            "sid": sid,
            "digest_algorithm": dg_algo,
            "signed_attrs": signed_attrs,
            "signature_algorithm": sig_algo,
            "signature": OctetString(sig),
            "unsigned_attrs": unsigned_attrs,
        }
    )

    certs = make_certificate_chain(cert)

    signed_data = SignedData(
        {
            "version": CMSVersion(1),
            "digest_algorithms": [dg_algo],
            "encap_content_info": ContentInfo({"content_type": ContentType("data")}),
            "certificates": certs,
            "signer_infos": [sig_info],
        }
    )

    return ContentInfo(
        {"content_type": ContentType.unmap("signed_data"), "content": signed_data}
    )


def get_timestamp_token(digest: bytes, hash_type: int):
    # Create a TimestampRequest
    dg_algo = DigestAlgorithm({"algorithm": _get_digest_algo(hash_type)})
    imprint = MessageImprint(
        {"hash_algorithm": dg_algo, "hashed_message": OctetString(digest)}
    )

    tsreq = TimeStampReq(
        {
            "version": Version(1),
            "message_imprint": imprint,
            "cert_req": True,
        }
    )

    # Send tsreq to the server
    headers = {"Content-Type": "application/timestamp-query"}
    resp = requests.post(TIMESTAMP_SERVER, data=tsreq.dump(), headers=headers)
    resp.raise_for_status()
    tsresp = TimeStampResp.load(resp.content)

    return tsresp["time_stamp_token"]


class SingleCodeSigner(object):
    def __init__(
        self,
        filename: str,
        macho_index: int,
        macho: MACHO,
        cert: Certificate,
        privkey: PrivateKeyInfo,
        reqs_path: Optional[str] = None,
        ents_path: Optional[str] = None,
        force: bool = False,
        detach_target: Optional[str] = None,
    ):
        self.filename: str = filename
        self.macho_index: int = macho_index
        self.macho: MACHO = macho
        self.cert: Certificate = cert
        self.privkey: PrivateKeyInfo = privkey
        self.detach_target = detach_target

        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.info_file_path = os.path.join(self.content_dir, "Info.plist")
        self.res_dir_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )
        if self.detach_target:
            self.res_dir_path = os.path.join(
                self.detach_target, "Contents", "_CodeSignature", "CodeResources"
            )

        self.reqs_path = reqs_path
        self.ents_path = ents_path

        with open(self.info_file_path, "rb") as f:
            self.info = plistlib.load(f, dict_type=OrderedDict)
        self.ident = self.info["CFBundleIdentifier"]
        self.team_id = self.cert.subject.native["organizational_unit_name"]

        self.hash_type = 2  # Use SHA256 hash
        self.hash_type_str = "sha256"
        self.page_size = PAGE_SIZES[self.macho.Mhdr.cputype]

        self.sig = EmbeddedSignatureBlob()
        self.sig.reqs_blob = RequirementsBlob()

        self.files_modified: List[str] = []

        if not force:
            sig_cmd = self.get_sig_command()
            if sig_cmd is not None:
                raise Exception(
                    "Binary already signed. Please use --force to ignore existing signatures"
                )

    def _set_info_hash(self):
        self.sig.code_dir_blob.info_hash = hash_file(
            self.info_file_path, self.hash_type
        )

    def _set_requirements(self):
        assert self.sig.reqs_blob
        assert self.sig.code_dir_blob
        if self.reqs_path is None:
            # Make default requirements set:
            # designated => identifier "<ident>" and anchor apple generic and leaf[subject.OU] = "<OU>"
            #
            # This requirement set is not the Apple default. What Apple actually uses for the default is hard to know.
            # From experimentation, it seems like this is a reasonable default, although Apple also sometimes uses the CN
            # instead of the OU. Additionally Apple requires some specific extensions exists in the intermediate certificates,
            # but I am not sure what those extensions are, how to determine what to set, and they seem unnecessary.
            r = Requirement(
                AndOrExpr(
                    ExprOp.OP_AND,
                    AndOrExpr(
                        ExprOp.OP_AND,
                        SingleArgExpr(ExprOp.OP_IDENT, self.ident.encode()),
                        Expr(ExprOp.OP_APPLE_GENERIC_ANCHOR),
                    ),
                    CertificateMatch(
                        ExprOp.OP_CERT_FIELD,
                        0,
                        b"subject.OU",
                        ArgMatchExpr(MatchOP.MATCH_EQUAL, self.team_id.encode()),
                    ),
                )
            )
            self.sig.reqs_blob.designated_req = RequirementBlob(r)
        else:
            with open(reqs_path, "rb") as f:
                self.sig.reqs_blob.deserialize(f)

        self.sig.code_dir_blob.reqs_hash = self.sig.reqs_blob.get_hash(self.hash_type)

    def _set_entitlements(self):
        if self.ents_path is None:
            # There are no default entitlements, just do nothing then
            return
        else:
            assert self.sig.code_dir_blob
            self.sig.ent_blob = EntitlementsBlob()
            with open(self.ents_path, "rb") as f:
                self.sig.ent_blob.deserialize(f)
            self.sig.code_dir_blob.ent_hash = self.sig.ent_blob.get_hash(self.hash_type)

    def _set_code_hashes(self):
        assert self.sig.code_dir_blob

        # Maybe the file got modified, so clear any hashes and recompute them all
        self.sig.code_dir_blob.code_hashes.clear()

        sig_offset = self.calculate_sig_offset()
        f = BytesIO(self.macho.pack())
        num_hashes = round_up(sig_offset, self.page_size) // self.page_size
        read = 0
        for i in range(num_hashes):
            to_read = self.page_size
            if read + to_read > sig_offset:
                to_read = sig_offset - read

            data = f.read(to_read)
            read += to_read
            self.sig.code_dir_blob.code_hashes.append(get_hash(data, self.hash_type))

    def _set_code_res_hash(self):
        self.sig.code_dir_blob.res_dir_hash = hash_file(
            self.res_dir_path, self.hash_type
        )

    def make_code_directory(self):
        build_meta = [
            cmd for cmd in self.macho.load.lhlist if cmd.cmd == LC_BUILD_VERSION
        ]
        if len(build_meta) == 0:
            platform = 0
        else:
            assert len(build_meta) == 1
            platform = build_meta[0].platform

        self.sig.code_dir_blob = CodeDirectoryBlob()

        self.sig.code_dir_blob.version = CodeDirectoryBlob.CDVersion.LATEST
        self.sig.code_dir_blob.flags = 0
        self.sig.code_dir_blob.code_limit = self.calculate_sig_offset()
        self.sig.code_dir_blob.hash_size = len(get_hash(b"", self.hash_type))
        self.sig.code_dir_blob.hash_type = self.hash_type
        self.sig.code_dir_blob.platform = platform
        self.sig.code_dir_blob.page_size = CODE_DIR_PAGE_SIZES[self.page_size]
        self.sig.code_dir_blob.spare2 = 0
        self.sig.code_dir_blob.scatter_offset = 0
        self.sig.code_dir_blob.spare3 = 0
        self.sig.code_dir_blob.code_limit_64 = 0
        self.sig.code_dir_blob.exec_seg_base = 0
        self.sig.code_dir_blob.exec_seg_limit = 0
        self.sig.code_dir_blob.exec_seg_flags = 0
        self.sig.code_dir_blob.runtime = 0
        self.sig.code_dir_blob.pre_encrypt_offset = 0

        self.sig.code_dir_blob.ident = self.ident.encode()
        self.sig.code_dir_blob.team_id = self.team_id.encode()

        # Do the special hashes first
        self._set_info_hash()
        self._set_requirements()
        self._set_code_res_hash()
        self._set_entitlements()

        # Do the code hashes
        self._set_code_hashes()

    def get_size_estimate(self):
        assert self.sig.code_dir_blob

        # Estimate the size
        v = BytesIO()
        self.sig.serialize(v)
        return len(v.getvalue()) + 18000  # Apple uses 18000 for the CMS sig estimate

    def get_sig_command(self):
        sig_cmds = [
            cmd for cmd in self.macho.load.lhlist if cmd.cmd == LC_CODE_SIGNATURE
        ]
        if len(sig_cmds) == 1:
            return sig_cmds[0]
        else:
            return None

    def get_linkedit_segment(self):
        seg_cmds = [
            cmd
            for cmd in self.macho.load.lhlist
            if isinstance(cmd, segment_command) and cmd.segname == "__LINKEDIT"
        ]
        assert len(seg_cmds) == 1, "Could not find __LINKEDIT segment"
        return seg_cmds[0]

    def calculate_sig_offset(self):
        sig_cmd = self.get_sig_command()
        if sig_cmd is not None:
            # We have a sig command, get the offset from there
            return sig_cmd.dataoff

        ls_seg = self.get_linkedit_segment()
        return round_up(ls_seg.fileoff + ls_seg.filesize, 16)

    def make_signature(self):
        assert self.sig.code_dir_blob

        # Redo the code hashes
        self._set_code_hashes()

        # Make the signature
        signed_attrs: CMSAttributes = make_signed_attrs(
            self.sig.code_dir_blob.get_hash(self.hash_type), self.hash_type
        )
        actual_privkey = load_private_key(self.privkey)
        signature = rsa_pkcs1v15_sign(
            actual_privkey, signed_attrs.dump(), self.hash_type_str
        )

        # Get the timestamp from Apple
        digest = get_hash(signature, self.hash_type)
        tst = CMSAttribute(
            {
                "type": CMSAttributeType("signature_time_stamp_token"),
                "values": [get_timestamp_token(digest, self.hash_type)],
            }
        )

        # Make the CMS
        self.sig.sig_blob = SignatureBlob()
        self.sig.sig_blob.cms = make_cms(
            self.cert, self.hash_type, signed_attrs, signature, CMSAttributes([tst])
        )

        # Get the CodeSignature section. It should be the last in the binary
        cs_sec = self.macho.sect[-1]
        assert cs_sec == self.get_linkedit_segment().sect[-1]
        assert isinstance(cs_sec, CodeSignature)
        sig_cmd = self.get_sig_command()

        # Serialize the signature
        f = BytesIO()
        self.sig.serialize(f)
        f.write((sig_cmd.datasize - f.tell()) * b"\x00")

        if self.detach_target:
            target_dir = os.path.join(self.detach_target, "Contents", "MacOS")
            os.makedirs(target_dir, exist_ok=True)
            target_file = os.path.join(
                target_dir,
                os.path.basename(self.filename)
                + f".{CPU_NAMES[self.macho.Mhdr.cputype]}sign",
            )
            with open(target_file, "wb") as tf:
                tf.write(f.getvalue())
                self.files_modified.append(target_file)
        else:
            # Set the section's content to be the signature
            cs_sec.content = StrPatchwork(f.getvalue())

    def write_file_list(self, file_list: str):
        with open(file_list, "a") as f:
            for l in self.files_modified:
                f.write(l + "\n")


class CodeSignatureAttacher(SingleCodeSigner):
    def __init__(
        self,
        filename: str,
        macho_index: int,
        macho: MACHO,
        sig_path: str,
    ):
        self.filename = filename
        self.macho_index = macho_index
        self.macho = macho
        self.sig_path = sig_path
        self.page_size = PAGE_SIZES[self.macho.Mhdr.cputype]

        with open(self.sig_path, "rb") as f:
            self.sig_data = f.read()

    def make_code_directory(self):
        pass

    def get_size_estimate(self):
        return len(self.sig_data)

    def make_signature(self):
        """
        Attaches the signature
        """
        # Get the CodeSignature section. It should be the last in the binary
        cs_sec = self.macho.sect[-1]
        assert cs_sec == self.get_linkedit_segment().sect[-1]
        assert isinstance(cs_sec, CodeSignature)
        sig_cmd = self.get_sig_command()

        # Set the section's content to be the signature
        cs_sec.content = StrPatchwork(self.sig_data)


class CodeSigner(object):
    def __init__(
        self,
        filename: str,
        cert: Certificate,
        privkey: PrivateKeyInfo,
        force: bool = False,
        detach_target: Optional[str] = None,
    ):
        self.filename = filename
        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.cert = cert
        self.privkey = privkey
        self.force = force
        self.detach_target = detach_target

        self.hash_type = 2

        self.code_signers: List[SingleCodeSigner] = []

        self.files_modified: List[str] = []

        with open(self.filename, "rb") as f:
            self.macho = MACHO(f.read())

    def _hash_name(self) -> str:
        """
        Get the name of the hash for use in CodeResources
        """
        if self.hash_type == 1:  # SHA1 is just called "hash"
            return "hash"
        return f"hash{self.hash_type}"  # The rest is called "hashn" where n is the type value

    def _build_resources(self):
        resource_dir = os.path.join(self.content_dir, "Resources")

        # Build the resource rules
        # TODO: Resource rules can be embedded in some places. Figure out how to deal with those.
        # For now, we just use the default resource rules from Security/OSX/libsecurity_codesigning/lib/bundlediskrep.cpp
        rules: Dict[str, Dict[str, Any]] = {
            "rules": {
                "^version.plist$": True,
                "^Resources/": True,
                "^Resources/.*\.lproj": {
                    "optional": True,
                    "weight": 1000,
                },
                "^Resources/Base\.lproj/": {
                    "weight": 1010,
                },
                "^Resources/.*\.lproj/locversion.plist$": {
                    "omit": True,
                    "weight": 1100,
                },
            },
            "rules2": {
                "^.*": True,
                "^[^/]+$": {
                    "nested": True,
                    "weight": 10,
                },
                "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/": {
                    "nested": True,
                    "weight": 10,
                },
                ".*\.dSYM($|/)": {
                    "weight": 11,
                },
                "^(.*/)?\.DS_Store$": {
                    "omit": True,
                    "weight": 2000,
                },
                "^Info\.plist$": {
                    "omit": True,
                    "weight": 20,
                },
                "^version\.plist$": {
                    "weight": 20,
                },
                "^embedded\.provisionprofile$": {
                    "weight": 20,
                },
                "^PkgInfo$": {
                    "omit": True,
                    "weight": 20,
                },
                "^Resources/": {
                    "weight": 20,
                },
                "^Resources/.*\.lproj/<": {
                    "optional": True,
                    "weight": 1000,
                },
                "^Resources/Base\.lproj/": {
                    "weight": 1010,
                },
                "^Resources/.*\.lproj/locversion.plist$": {
                    "omit": True,
                    "weight": 1100,
                },
            },
        }

        def _find_rule(path: str) -> Optional[Tuple[str, Any, Any]]:
            """
            Finds the rule for the path.
            Returns None if no rule matches or this path should be excluded.
            """
            best_rule = None
            for k, v in rules["rules2"].items():
                weight = v["weight"] if isinstance(v, dict) and "weight" in v else 1
                if re.match(k, path):
                    if best_rule is None or weight > best_rule[2]:
                        best_rule = k, v, weight

            if best_rule:
                if (
                    isinstance(best_rule[1], dict)
                    and "omit" in best_rule[1]
                    and best_rule[1]["omit"]
                ):
                    return None

            return best_rule

        code_sig_dir = os.path.join(self.content_dir, "_CodeSignature")
        macos_dir = os.path.join(self.content_dir, "MacOS")

        # Following the rules that we just set, build the resources file
        resources: Dict[str, Dict[str, Union[str, Dict[str, str]]]] = {
            "files": {},
            "files2": {},
        }
        for file_path in glob.iglob(
            os.path.join(self.content_dir, "**"), recursive=True
        ):
            # TODO: Handle symlinks and all of the other stuff (libs, frameworks, etc.) for more complicated programs

            # Exclude _CodeSignature and MacOS directories
            if os.path.commonpath([code_sig_dir, file_path]) == code_sig_dir:
                continue
            elif os.path.commonpath([macos_dir, file_path]) == macos_dir:
                continue

            rel_path = os.path.relpath(file_path, self.content_dir)
            if os.path.isfile(file_path):
                rule = _find_rule(rel_path)
                if rule is not None:
                    # Add the path
                    file_hash = hash_file(file_path, self.hash_type)
                    file_sha1 = hash_file(file_path, 1)  # Always have to hash with sha1
                    resources["files"][
                        rel_path
                    ] = file_sha1  # This is a legacy format that only supports SHA1
                    resources["files2"][rel_path] = {self._hash_name(): file_hash}

        # Make the final resources data
        resources["rules"] = rules["rules"]
        resources["rules2"] = rules["rules2"]

        # Make the _CodeSignature folder and write out the resources file
        if self.detach_target:
            target_dir = os.path.join(self.detach_target, "Contents", "_CodeSignature")
        else:
            target_dir = code_sig_dir
        os.makedirs(target_dir, exist_ok=True)
        cr_path = os.path.join(target_dir, "CodeResources")
        with open(cr_path, "wb") as f:
            plistlib.dump(resources, f, fmt=plistlib.FMT_XML)
            self.files_modified.append(cr_path)

    def allocate(self):
        for cs in self.code_signers:
            # Get fresh calculations of offset and size
            sig_offset = cs.calculate_sig_offset()
            sig_size = cs.get_size_estimate()
            sig_end = sig_offset + sig_size

            # Get the linkedit segment
            linkedit_seg = cs.get_linkedit_segment()
            linkedit_end = linkedit_seg.fileoff + linkedit_seg.filesize

            cmd = cs.get_sig_command()
            if cmd is not None:
                # Existing sig command. Get the CodeSignature section. It should be last one in the binary.
                cs_sec = cs.macho.sect[-1]
                sig_size = sig_size if sig_size > cmd.datasize else cmd.datasize
            else:
                # No existing sig command, so add one.
                cmd = linkedit_data_command(cmd=LC_CODE_SIGNATURE, parent=cs.macho.load)

                # Add the load command
                cs.macho.load.append(cmd)

                # Create a CodeSignature section
                cs_sec = CodeSignature(parent=cmd)

                # Add it to the binary
                # Note, don't use linkedit_seg.addSH because linkedit doesn't actually have segments.
                linkedit_seg.sect.append(cs_sec)
                cs.macho.sect.add(cs_sec)

            # Set the size, offset, and empty content of the CodeSignature section
            cmd.dataoff = sig_offset
            cmd.datasize = sig_size
            cs_sec.size = sig_size
            cs_sec.offset = sig_offset
            cs_sec.content = StrPatchwork(sig_size * b"\x00")

            # increase linkedit size
            end_diff = sig_end - linkedit_end
            if end_diff > 0:
                linkedit_seg.filesize += end_diff
                linkedit_seg.vmsize = round_up(linkedit_seg.filesize, cs.page_size)

    def make_signature(self):
        """
        Signs the filename in place
        """
        # Open the MachO and prepare the code signer for each embedded binary
        # Get all of the size estimates
        arch_sizes: Dict[int, int] = {}  # cputype: sig size
        for i, h in enumerate(get_macho_list(self.macho)):
            cs = SingleCodeSigner(
                self.filename,
                i,
                h,
                self.cert,
                self.privkey,
                force=self.force,
                detach_target=self.detach_target,
            )
            self.code_signers.append(cs)

        # Make CodeResources
        self._build_resources()

        for cs in self.code_signers:
            cs.make_code_directory()

        self.apply_signature()

    def apply_signature(self):
        # Allocate space in the binary for all of the signatures
        self.allocate()

        # Make the final signatures and add it to the binaries
        for cs in self.code_signers:
            cs.make_signature()

        if not self.detach_target:
            # Fix the fat header because offsets may have moved
            if hasattr(self.macho, "Fhdr"):
                for cs in self.code_signers:
                    self.macho.fh[cs.macho_index].size = len(cs.macho.pack())
                p = 0
                for h, m in zip(self.macho.fh, self.macho.arch.macholist):
                    if p > h.offset:
                        h.offset = round_up(p, 2 ** h.align)
                        m.offset = h.offset
                    p = h.offset + h.size

            # Write out the final macho
            with open(self.filename, "wb") as f:
                data = self.macho.pack()
                f.write(data)
                self.files_modified.append(self.filename)

    def write_file_list(self, file_list: str):
        with open(file_list, "a") as f:
            for l in self.files_modified:
                f.write(l + "\n")

        for cs in self.code_signers:
            cs.write_file_list(file_list)


def sign_mach_o(
    filename: str,
    p12_path: str,
    passphrase: Optional[str] = None,
    force: bool = False,
    file_list: Optional[str] = None,
    detach_target: Optional[str] = None,
):
    """
    Code sign a Mach-O binary in place
    """
    bundle, filepath = get_bundle_exec(filename)

    if passphrase is None:
        passphrase = getpass.getpass(f"Enter the passphrase for {p12_path}: ")
    pass_bytes = passphrase.encode()

    # Load cert and privkey
    with open(p12_path, "rb") as f:
        privkey, cert, _ = parse_pkcs12(f.read(), pass_bytes)

    # Include the bundle name in the detached target
    if detach_target:
        detach_target = os.path.join(detach_target, os.path.basename(bundle))

    # Sign
    cs = CodeSigner(filepath, cert, privkey, force=force, detach_target=detach_target)
    cs.make_signature()

    if file_list is not None:
        cs.write_file_list(file_list)


def apply_sig(filename: str, detach_path: str):
    """
    Attach the signature for the bundle of the same name at the detach_path
    """
    bundle, filepath = get_bundle_exec(filename)
    detach_bundle = os.path.join(detach_path, os.path.basename(bundle))

    bin_code_signers: Dict[str, CodeSigner] = {}

    for file_path in glob.iglob(os.path.join(detach_bundle, "**"), recursive=True):
        if os.path.isdir(file_path):
            continue
        bundle_relpath = os.path.relpath(file_path, detach_bundle)
        bundle_path = os.path.join(bundle, bundle_relpath)

        if os.path.basename(os.path.dirname(file_path)) == "MacOS":
            # Signature files are only in the MacOS dir
            if file_path.endswith("sign"):
                bin_name, ext = os.path.splitext(file_path)

                bundle_relpath = os.path.relpath(bin_name, detach_bundle)
                bundle_path = os.path.join(bundle, bundle_relpath)

                if bin_name not in bin_code_signers:
                    bin_code_signers[bin_name] = CodeSigner(
                        bundle_path, Certificate(), PrivateKeyInfo()
                    )
                bcs = bin_code_signers[bin_name]

                # Figure out which index this sig is for
                idx = 0
                macho = bcs.macho
                if hasattr(bcs.macho, "Fhdr"):
                    if ext == ".sign":
                        raise Exception(
                            "Cannot attach single architecture signature to universal binary"
                        )
                    arch_type = CPU_NAME_TO_TYPE[ext[1:-4]]
                    for i, h in enumerate(bcs.macho.fh):
                        if h.cputype == arch_type:
                            idx = i
                            macho = bcs.macho.arch[i]
                            break
                else:
                    # For thin binaries, make sure only one signature is being attached
                    if len(bcs.code_signers) > 0:
                        raise Exception(
                            "Signature already being attached to thin binary"
                        )

                # Create a CodeSignatureAttacher
                csa = CodeSignatureAttacher(bundle_path, idx, macho, file_path)

                # Add it to the CodeSigner
                bcs.code_signers.append(csa)

                continue

        # Non-signature files are just copied over
        os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
        shutil.copyfile(file_path, bundle_path)

    # Apply the signature for all CodeSigners
    for _, cs in bin_code_signers.items():
        cs.apply_signature()
