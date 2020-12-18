import getpass
import glob
import os
import plistlib
import subprocess
import re

from asn1crypto.algos import DigestAlgorithmId, SignedDigestAlgorithmId
from asn1crypto.core import ObjectIdentifier, OctetString, Sequence, SetOf, UTCTime
from asn1crypto.cms import (
    CMSAttribute,
    CMSAttributes,
    CMSAttributeType,
    CMSVersion,
    ContentInfo,
    ContentType,
    IssuerAndSerialNumber,
    SetOfAny,
    SignedData,
    SignerIdentifier,
    SignerInfo,
)
from asn1crypto.x509 import Certificate
from asn1crypto.keys import PrivateKeyInfo
from collections import OrderedDict
from datetime import datetime, timezone
from macholib.MachO import MachO, MachOHeader
from macholib.mach_o import CPU_TYPE_NAMES, LC_CODE_SIGNATURE, linkedit_data_command
from oscrypto import asymmetric
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
from .utils import get_hash, hash_file, round_up


HASH_AGILITY_V1_OID = CMSAttributeType("1.2.840.113635.100.9.1")
HASH_AGILITY_V2_OID = CMSAttributeType("1.2.840.113635.100.9.2")

PAGE_SIZES = {
    0x01000007: 0x1000,  # AMD64
    0x01000012: 0x4000,  # ARM64
}


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
    iss_ser = IssuerAndSerialNumber(cert.native["issuer"], cert.native["serial_number"])
    sid = SignerIdentifier("issuer_and_serial_number", iss_ser)

    dg_algo = _get_digest_algo(hash_type)

    sig_algo = SignedDigestAlgorithmId.unmap("rsassa_pkcs1v15")

    sig_info = SignerInfo(
        {
            "version": CMSVersion.unmap("v1"),
            "sid": sid,
            "digest_algorithm": dg_algo,
            "signed_attrs": signed_attrs,
            "signature_algorithm": sig_algo,
            "signature": sig,
            "unsigned_attrs": unsigned_attrs,
        }
    )

    certs = make_certificate_chain(cert)

    signed_data = SignedData(
        {
            "version": CMSVersion.unmap("v1"),
            "digest_algorithms": [dg_algo],
            "enap_content_info": None,
            "certificates": certs,
            "signer_infos": [sig_info],
        }
    )

    return ContentInfo(
        {"content_type": ContentType.unmap("signed_data"), "content": signed_data}
    )


class SingleCodeSigner(object):
    def __init__(
        self,
        filename: str,
        macho_index: int,
        macho_header: MachOHeader,
        cert: Certificate,
        privkey: PrivateKeyInfo,
        reqs_path: Optional[str] = None,
        ents_path: Optional[str] = None,
    ):
        self.filename: str = filename
        self.macho_index: int = macho_index
        self.macho_header: MachOHeader = macho_header
        self.cert: Certificate = cert
        self.privkey: PrivateKeyInfo = privkey

        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.info_file_path = os.path.join(self.content_dir, "Info.plist")
        self.res_dir_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )
        self.reqs_path = reqs_path
        self.ents_path = ents_path

        with open(self.info_file_path, "rb") as f:
            self.info = plistlib.load(f, dict_type=OrderedDict)
        self.ident = self.info["CFBundleIdentifier"]
        self.team_id = self.cert.subject.native["organizational_unit_name"]

        self.hash_type = 2  # Use SHA256 hash
        self.hash_type_str = "sha256"
        self.page_size = PAGE_SIZES[self.macho_header.header.cputype]

        self.sig = EmbeddedSignatureBlob()
        self.sig.reqs_blob = RequirementsBlob()

        self.sigmeta: Optional[Tuple[int, linkedit_data_command, bytes]] = None

    def _set_info_hash(self):
        self.sig.code_dir_blob.info_hash = hash_file(
            self.info_file_path, self.hash_type
        )

    def _set_requirements(self):
        assert self.sig.reqs_blob
        assert self.sig.code_dir_blob
        if reqs_path is None:
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

        with open(self.filename, "rb") as f:
            f.seek(self.macho_header.offset)
            num_hashes = round_up(self.macho_header.total_size, self.page_size)
            read = 0
            for i in range(num_hashes):
                to_read = self.page_size
                if read + to_read > self.macho_header.total_size:
                    to_read = self.macho_header.total_size - read

                data = f.read(to_read)
                read += to_read
                self.sig.code_dir_blob.code_hashes.append(
                    get_hash(data, self.hash_type)
                )

    def _set_code_res_hash(self):
        code_res_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )
        self.sig.code_dir_blob.res_dir_hash = hash_file(code_res_path, self.hash_type)

    def make_code_directory(self):
        build_meta = [
            cmd for cmd in self.macho_header.commands if cmd[0].cmd == LC_BUILD_VERSION
        ]
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

    def get_size_estimate(self):
        assert self.sig.code_dir_blob

        # Estimate the size
        v = BytesIO()
        self.sig.serialize(v)
        return len(v.getvalue()) + 18000  # Apple uses 18000 for the CMS sig estimate

    def _refresh_macho_header(self):
        macho = MachO(self.filename)
        self.macho_header = macho.headers[self.macho_index]
        sig_cmds = [cmd for cmd in h.commands if cmd[0].cmd == LC_CODE_SIGNATURE]
        assert len(sig_cmds) == 0
        self.sigmeta = sig_cmds[0]

    def make_signature(self, offset: int):
        assert self.sig.code_dir_blob

        # Refresh our MachOHeader
        self._refresh_macho_header()
        assert self.sigmeta

        # Redo the code hashes
        self._set_code_hashes()

        # Make the signature
        signed_attrs: CMSAttributes = make_signed_attrs(
            self.sig.code_dir_blob.get_hash(self.hash_type), self.hash_type
        )
        signature = asymmetric.rsa_pkcs1v15_sign(
            self.privkey, signed_attrs.dump(), self.hash_type_str
        )
        cms = make_cms(self.cert, self.hash_type, signed_attrs, signature, None)
        self.sig.sig_blob = SignatureBlob()
        self.sig.sig_blob.cms_data = cms

        # Attach the signature to the MachO binary
        offset = self.macho_header.offset + self.sigmeta[1].dataoff
        with open(self.filename, "rb+") as f:
            f.seek(offset)
            self.sig.serialize(f)


class CodeSigner(object):
    def __init__(self, filename: str, cert: Certificate, privkey: PrivateKeyInfo):
        self.filename = filename
        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.cert = cert
        self.privkey = privkey

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

    def _allocate(self, arch_sizes: Dict[int, int]):
        """
        Calls codesign_allocate to allocate space in the binary as specified in arch_sizes.
        After doing this, each SingleCodeSigner will need to refresh it's macho header to know
        where to put the signature
        """
        # Get the codesign_allocate binary to run
        alloc_tool = os.getenv("CODESIGN_ALLOCATE", "codesign_allocate")

        # Create the command to run
        # Note that we will modify in place
        args = [alloc_tool, "-i", self.filename, "-o", self.filename]
        for a, s in arch_sizes.items():
            args.append("-a")
            args.append(CPU_TYPE_NAMES[a])
            args.append(str(s))

        # Run it
        subprocess.check_call(args)

    def make_signature(self):
        """
        Signs the filename in place
        """
        # Make CodeResources
        self._build_resources()

        # Open the MachO and prepare the code signer for each embedded binary
        # Get all of the size estimates
        macho = MachO(self.filename)
        code_signers: List[SingleCodeSigner] = []
        arch_sizes: Dict[int, int] = {}  # cputype: sig size
        for i, h in enumerate(macho.headers):
            cs = SingleCodeSigner(self.filename, i, h, self.cert, self.privkey)
            cs.make_code_directory()
            code_signers.append(cs)

            arch_sizes[h.header.cputype] = cs.get_size_estimate()

        # Allocate space in the binary for all of the signatures
        # After this point, macho is no longer valid and cannot be used further
        self._allocate(arch_sizes)

        # Make the final signatures and add it to the binaries
        for cs in code_signers:
            cs.make_signature()


def sign_mach_o(filename: str, p12_path: str, passphrase: Optional[str] = None):
    """
    Code sign a Mach-O binary in place
    """
    abs_path = os.path.abspath(filename)

    if passphrase is None:
        passphrase = getpass.getpass(f"Enter the passphrase for {p12_path}: ")

    # Load cert and privkey
    with open(p12_path, "rb") as f:
        privkey, cert, _ = parse_pkcs12(f.read(), passphrase)

    # Sign
    cs = CodeSigner(abs_path, cert, privkey)
    cs.make_signature()
