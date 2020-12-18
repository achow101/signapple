import glob
import os
import plistlib
import re

from asn1crypto.algos import DigestAlgorithmId, SignedDigestAlgorithmId  # type: ignore
from asn1crypto.core import ObjectIdentifier, OctetString, Sequence, SetOf, UTCTime  # type: ignore
from asn1crypto.cms import CMSAttribute, CMSAttributes, CMSAttributeType, ContentInfo, ContentType, SetOfAny  # type: ignore
from asn1crypto.x509 import Certificate  # type: ignore
from asn1crypto.keys import PrivateKeyInfo  # type: ignore
from collections import OrderedDict
from datetime import datetime, timezone
from macholib.MachO import MachO  # type: ignore
from macholib.mach_o import LC_CODE_SIGNATURE, linkedit_data_command  # type: ignore
from typing import Any, Dict, List, Optional, Tuple

from .blobs import (
    EmbeddedSignatureBlob,
    EntitlementsBlob,
    CodeDirectoryBlob,
    RequirementsBlob,
    RequirementBlob,
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
from .utils import get_hash, hash_file


HASH_AGILITY_V1_OID = CMSAttributeType("1.2.840.113635.100.9.1")
HASH_AGILITY_V2_OID = CMSAttributeType("1.2.840.113635.100.9.2")


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
    content_type = CMSAttribute({"type": CMSAttributeType.unmap("content_type"), "values": [ContentType.unmap("data")]})

    time_now = UTCTime()
    time_now.set(datetime.now(timezone.utc))
    signing_time = CMSAttribute({"type": CMSAttributeType.unmap("signing_time"), "values": [time_now]})

    message_digest = CMSAttribute({"type": CMSAttributeType.unmap("message_digest"), "values": [OctetString(digest)]})

    ha_v1 = make_hash_agility_v1(digest)

    ha_v2 = make_hash_agility_v2(digest, hash_type)

    return CMSAttributes([content_type, signing_time, message_digest, ha_v1, ha_v2])


def make_certificate_chain(cert):
    certs = [cert]
    for c in APPLE_INTERMEDIATES:
        if certs[-1].native["tbs_certificate"]["issuer"] == c.native["tbs_certificate"]["subject"]:
            certs.append(c)
            break
    for c in APPLE_ROOTS:
        if certs[-1].native["tbs_certificate"]["issuer"] == c.native["tbs_certificate"]["subject"]:
            certs.append(c)
            break
    return list(reversed(certs))


def make_cms(cert: Certificate, hash_type: int, signed_attrs: CMSAttributes, sig: bytes, unsigned_attrs: Optional[CMSAttributes]) -> ContentInfo:
    iss_ser = IssuerAndSerialNumber(cert.native["issuer"], cert.native["serial_number"])
    sid = SignerIdentifier("issuer_and_serial_number", iss_ser)

    dg_algo = _get_hash_type(hash_type)

    sig_algo = SignedDigestAlgorithmId.unmap("rsassa_pkcs1v15")

    sig_info = SignerInfo({
        "version": CMSVersion.unmap("v1"),
        "sid": sid,
        "digest_algorithm": dg_algo,
        "signed_attrs": signed_attrs,
        "signature_algorithm": sig_algo,
        "signature": sig,
        "unsigned_attrs": unsigned_attrs,
    })

    certs = make_certificate_chain(cert)

    signed_data = SignedData({
        "version": CMSVersion.unmap("v1"),
        "digest_algorithms": [dg_algo],
        "enap_content_info": None,
        "certificates": certs,
        "signer_infos": [sig_info],
        })

    return ContentInfo({"content_type": ContentType.unmap("signed_data"), "content": signed_data})


class SingleCodeSigner(object):
    def __init__(
        self,
        filename: str,
        macho: MachOHeader,
        page_size: int,
        cert: Certificate,
        privkey: PrivateKeyInfo,
    ):
        self.filename: str = filename
        self.cert: Certificate = cert
        self.privkey = privkey

        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.info_file_path = os.path.join(self.content_dir, "Info.plist")
        self.res_dir_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )

        with open(self.info_file_path, "rb") as f:
            self.info = plistlib.load(f, dict_type=OrderedDict)
        self.ident = self.info["CFBundleIdentifier"]
        self.team_id = self.cert.subject.native["organizational_unit_name"]

        self.hash_type = 2  # Use SHA256 hash
        self.hash_type_str = "sha256"
        self.page_size = page_size

        self.sig = EmbeddedSignatureBlob()
        self.sig.reqs_blob = RequirementsBlob()

        self.macho = macho
        self.sigmeta = None

    def _set_info_hash(self):
        self.sig.code_dir_blob.info_hash = hash_file(
            self.info_file_path, self.hash_type
        )

    def _set_requirements(self, filename: Optional[str] = None):
        assert self.sig.reqs_blob
        assert self.sig.code_dir_blob
        if filename is None:
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
                        SingleArgExpr(ExprOp.OP_IDENT, self.ident),
                        Expr(ExprOp.OP_APPLE_GENERIC_ANCHOR),
                    ),
                    CertificateMatch(
                        ExprOp.OP_CERT_FIELD,
                        0,
                        b"subject.OU",
                        ArgMatchExpr(MatchOP.MATCH_EQUAL, self.team_id),
                    ),
                )
            )
            self.sig.reqs_blob.designated_req = RequirementBlob(r)
        else:
            with open(filename, "rb") as f:
                self.sig.reqs_blob.deserialize(f)

        self.sig.code_dir_blob.reqs_hash = self.sig.reqs_blob.get_hash(self.hash_type)

    def _set_entitlements(self, filename: Optional[str] = None):
        if filename is None:
            # There are no default entitlements, just do nothing then
            return
        else:
            assert self.sig.code_dir_blob
            self.sig.ent_blob = EntitlementsBlob()
            with open(filename, "rb") as f:
                self.sig.ent_blob.deserialize(f)
            self.sig.code_dir_blob.ent_hash = self.sig.ent_blob.get_hash(self.hash_type)

    def _set_code_hashes(self):
        assert self.sig.code_dir_blob

        # Maybe the file got modified, so clear any hashes and recompute them all
        self.sig.code_dir_blob.code_hashes.clear()

        # Write the macho to bytes, then do the hashes
        v = BytesIO()
        self.macho_header.write(v)

        v.seek(0)
        while True:
            data = v.read(self.page_size)
            if data.empty():
                break
            self.sig.code_dir_blob.code_hashes.append(get_hash(data, self.hash_type))

    def _set_code_res_hash(self):
        code_res_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )
        self.sig.code_dir_blob.res_dir_hash = hash_file(code_res_path, self.hash_type)

    def _prepare_macho(self, datasize: int = 0):
        """
        Add LC_CODE_SIGNATURE load command and set code limit.
        Doesn't use real values or actually add space for the code signature
        """
        sigmeta = [
            cmd for cmd in self.macho_header.commands if cmd[0].cmd == LC_CODE_SIGNATURE
        ]
        if len(sigmeta) == 1:
            cmd = sigmeta[0][1]
            cmd.datasize = datasize
        else:
            cmd = linkedit_data_command(dataoff=0, datasize=datasize)
            self.macho_header.append(cmd)
        self.macho_header.synchronize_size()
        cmd.dataoff = round(self.macho_header.total_size, 16)
        self.macho_header.synchronize_size()
        self.sigmeta = sigmeta

    def _make_code_directory(self):
        self._prepare_macho()

        build_meta = [cmd for cmd in h.commands if cmd[0].cmd == LC_BUILD_VERSION]
        assert len(build_meta) == 0
        platform = build_meta[0][1].platform

        self.sig.code_dir_blob = CodeDirectoryBlob()

        self.sig.code_dir_blob.version = CodeDirectoryBlob.CDVersion.LATEST
        self.sig.code_dir_blob.flags = 0
        self.sig.code_dir_blob.code_limit = self.macho_header.total_size
        self.sig.code_dir_blob.hash_size = len(get_hash(b"", self.hash_type))
        self.sig.code_dir_blob.hash_type = self.hash_type
        self.sig.code_dir_blob.platform = platform
        self.sig.code_dir_blob.page_size = self.page_size
        self.sig.code_dir_blob.spare2 = 0
        self.sig.code_dir_blob.scatter_offset = 0
        self.sig.code_dir_blob.spare3 = 0
        self.sig.code_dir_blob.code_limit_64 = 0
        self.sig.code_dir_blob.exec_seg_base = 0
        self.sig.code_dir_blob.exec_seg_limit = 0
        self.sig.code_dir_blob.exec_segflags = 0
        self.sig.code_dir_blob.runtime = 0
        self.sig.code_dir_blob.pre_encrypt_offset = 0

        self.sig.code_dir_blob.ident = self.ident
        self.sig.code_dir_blob.team_id = self.team_id

        # Do the special hashes first
        self._set_info_hash()
        self._set_requirements()
        self._set_code_res_hash()
        self._set_entitlements()

        # Do the code hashes
        self._set_code_hashes()

    def make_signature(self):
        # Make most of the stuff with make_code_directory
        self._make_code_directory()

        # Estimate the size
        v = BytesIO()
        self.sig.serialize(v)
        sig_size_est = (
            len(v.getvalue()) + 18000
        )  # Apple uses 18000 for the CMS sig estimate

        # Allocate space in the binary and redo the code hashes
        self._prepare_macho(sig_size_est)
        self._set_code_hashes()

        # Make the signature
        signed_attrs: CMSAttributes = make_signed_attrs(self.sig.code_dir_blob.get_hash(self.hash_type), self.hash_type)
        signature = asymmetric.rsa_pkcs1v15_sign(self.privkey, signed_attrs.dump(), self.hash_type_str)
        cms = make_cms(self.cert, self.hash_type, signed_attrs, signature, None)
        self.sig.sig_blob = SignatureBlob()
        self.sig.sig_blob.cms_data = cms

        # Attach the signature to the MachO binary
        v = BytesIO()
        self.sig.serialize(v)
        self.sigmeta[1].datasize = len(v.getvalue())
        self.sigmeta[2] = v.getvalue()
        # TODO: Finish


class CodeSigner(object):
    def __init__(self, filename: str, cert_chain: List[Certificate]):
        self.filename = filename
        self.cert_chain = cert_chain

        self.hash_type = 2

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
        if os.path.exists(resource_dir):
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
        else:
            rules: Dict[str, Dict[str, Any]] = {
                "rules": {
                    "^version.plist$": True,
                    "^.*": True,
                    "^.*\.lproj": {
                        "optional": True,
                        "weight": 1000,
                    },
                    "^Base\.lproj/": {
                        "weight": 1010,
                    },
                    "^.*\.lproj/locversion.plist$": {
                        "omit": True,
                        "weight": 1100,
                    },
                },
                "rules2": {
                    "^.*": True,
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
                    "^.*\.lproj/<": {
                        "optional": True,
                        "weight": 1000,
                    },
                    "^Base\.lproj/": {
                        "weight": 1010,
                    },
                    "^.*\.lproj/locversion.plist$": {
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
                print(rel_path)
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
        os.makedirs(code_sig_dir, exist_ok=True)
        with open(os.path.join(code_sig_dir, "CodeResources"), "wb") as f:
            plistlib.dump(f, resources, fmt=plistlib.FMT_XML)
