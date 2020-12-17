import glob
import os
import plistlib
import re

from asn1crypto.x509 import Certificate  # type: ignore
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from .blobs import (
    EmbeddedSignatureBlob,
    EntitlementsBlob,
    CodeDirectoryBlob,
    RequirementsBlob,
    RequirementBlob,
)
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


class CodeSigner(object):
    def __init__(self, filename: str, cert_chain: List[Certificate]):
        self.filename: str = filename
        self.cert_chain: List[Certificate] = cert_chain

        self.content_dir = os.path.dirname(os.path.dirname(os.path.abspath(filename)))
        self.info_file_path = os.path.join(self.content_dir, "Info.plist")
        self.res_dir_path = os.path.join(
            self.content_dir, "_CodeSignature", "CodeResources"
        )

        with open(self.info_file_path, "rb") as f:
            self.info = plistlib.load(f, dict_type=OrderedDict)
        self.ident = self.info["CFBundleIdentifier"]

        self.hash_type = 2  # Use SHA256 hash

        self.sig = EmbeddedSignatureBlob()
        self.sig.reqs_blob = RequirementsBlob()

        self.sig.code_dir_blob = CodeDirectoryBlob()
        self.sig.code_dir_blob.ident = self.ident
        self.sig.code_dir_blob.hash_type = self.hash_type
        self.sig.code_dir_blob.hash_size = len(get_hash(b"", self.hash_type))

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
                        ArgMatchExpr(
                            MatchOP.MATCH_EQUAL,
                            self.cert_chain[-1].subject.native[
                                "organizational_unit_name"
                            ],
                        ),
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
        res_data = plistlib.dumps(resources, fmt=plistlib.FMT_XML)
        self.sig.code_dir_blob.res_dir_hash = get_hash(res_data, self.hash_type)

        # Make the _CodeSignature folder and write out the resources file
        os.makedirs(code_sig_dir, exist_ok=True)
        with open(os.path.join(code_sig_dir, "CodeResources"), "wb") as f:
            f.write(res_data)
