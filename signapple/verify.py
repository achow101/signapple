import io
import macholib
import os

from asn1crypto.cms import CMSAttributes, SignedData
from asn1crypto.x509 import Certificate
from certvalidator.context import ValidationContext
from certvalidator import CertificateValidator
from macholib.MachO import MachO, MachOHeader
from macholib.mach_o import LC_CODE_SIGNATURE
from oscrypto import asymmetric
from typing import BinaryIO

from .blobs import (
    Blob,
    CodeDirectoryBlob,
    EmbeddedSignatureBlob,
    SignatureBlob,
    RequirementsBlob,
)
from .certs import APPLE_ROOTS, APPLE_INTERMEDIATES
from .utils import get_hash, get_bundle_exec, hash_file, sread

# OIDs fpr Apple's custom certificate critical extensions
# See the "Certificate Profile" sections of https://images.apple.com/certificateauthority/pdf/Apple_WWDR_CPS_v1.22.pdf
# and https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v3.1.pdf
APPLE_CERT_CRIT_EXTS = set(
    [
        "1.2.840.113635.100.6.1.4",  # iPhone Software Submission Signing
        "1.2.840.113635.100.6.1.2",  # iPhone Software Development Signing
        "1.2.840.113635.100.6.1.12",  # Mac Application Software Development Signing
        "1.2.840.113635.100.6.1.7",  # Mac Application Software Submission Signing
        "1.2.840.113635.100.6.1.8",  # Mac Application Package Submission Signing
        "1.2.840.113635.100.6.1.24",  # "Apple custom extension" for tvOS Application Signing Certificates
        "1.2.840.113635.100.6.1.14",  # "Apple custom extension" for Installer Package Signing Certificatesi
        "1.2.840.113635.100.6.1.13",  # "Apple custom extension" for Application Code Signing Certificatesi
    ]
)


def _validate_code_hashes(s: BinaryIO, cd_blob: CodeDirectoryBlob):
    # Code hashes
    assert cd_blob.page_size
    assert cd_blob.hash_type
    assert cd_blob.code_limit
    page_size = 2 ** cd_blob.page_size
    read = 0
    for slot_hash in cd_blob.code_hashes:
        to_read = page_size
        if read + page_size >= cd_blob.code_limit:
            to_read = cd_blob.code_limit - read

        this_hash = get_hash(sread(s, to_read), cd_blob.hash_type)
        read += to_read
        if slot_hash != this_hash:
            raise Exception(
                f"Code slot hash mismatch. Expected {slot_hash.hex()}, Calculated {this_hash.hex()}"
            )


def _validate_file_hash(file_path: str, target_hash: bytes, hash_type: int):
    this_hash = hash_file(file_path, hash_type)
    if target_hash != this_hash:
        raise Exception(
            f"{file_path} Hash mismatch. Expected {target_hash.hex()}, Calculated {this_hash.hex()}"
        )


def _validate_blob_hash(blob: Blob, target_hash: bytes, hash_type: int):
    """
    Hash a blob and check it. Use for several blobs.
    """
    this_hash = blob.get_hash(hash_type)
    if this_hash != target_hash:
        raise Exception(
            f"Blob (magic {hex(blob.magic)}) hash mismatch. Expected {target_hash.hex()}, calculated {this_hash.hex()}"
        )


def _sort_attributes(attrs_in: CMSAttributes) -> CMSAttributes:
    """
    Sort the authenticated attributes for signing by re-encoding them, asn1crypto
    takes care of the actual sorting of the set.
    """
    attrs_out = CMSAttributes()
    for attrval in attrs_in:
        attrs_out.append(attrval)
    return attrs_out


def _validate_cms_signature(sig_blob: SignatureBlob, cd_hash: bytes):
    signed_data = sig_blob.cms["content"]
    assert isinstance(signed_data, SignedData)
    assert len(signed_data["signer_infos"]) == 1

    # Get certificates
    cert_chain = []
    for cert in signed_data["certificates"]:
        c = cert.chosen
        assert isinstance(c, Certificate)
        cert_chain.append(c)

    # Get algorithms used
    signer_info = signed_data["signer_infos"][0]
    digest_alg = signer_info["digest_algorithm"]["algorithm"].native
    sig_alg = signer_info["signature_algorithm"]["algorithm"].native

    # Get message and signature
    signed_attrs = signer_info["signed_attrs"]
    sig = signer_info["signature"].contents

    # Check the hash of CodeDirectory matches what is in the signature
    message_digest = None
    for attr in sig_blob.cms["content"]["signer_infos"][0]["signed_attrs"]:
        if attr["type"].native == "message_digest":
            message_digest = attr["values"][0].native
            if message_digest != cd_hash:
                raise Exception(
                    f"CodeDirectory Hash mismatch. Expected {message_digest.hex()}, Calculated {cd_hash.hex()}"
                )
    if message_digest is None:
        raise Exception("message_digest not found in signature")

    # Validate the certificate chain
    validation_context = ValidationContext(
        trust_roots=APPLE_ROOTS,
        allow_fetching=False,
        additional_critical_extensions=APPLE_CERT_CRIT_EXTS,
    )
    validator = CertificateValidator(
        cert_chain[-1], cert_chain[0:-1], validation_context
    )
    validator.validate_usage({"digital_signature"}, {"code_signing"})

    # Check the signature
    pubkey = asymmetric.load_public_key(cert_chain[-1].public_key)
    signed_msg = _sort_attributes(signed_attrs).dump()
    asymmetric.rsa_pkcs1v15_verify(pubkey, sig, signed_msg, digest_alg)


def _verify_single(filename: str, h: MachOHeader):
    # Get the offset of the signature from the header
    # It is under the LC_CODE_SIGNATURE command
    sigmeta = [cmd for cmd in h.commands if cmd[0].cmd == LC_CODE_SIGNATURE]
    if len(sigmeta) == 0:
        raise Exception("No embedded code signature sections")
    elif len(sigmeta) > 1:
        raise Exception("Multiple embedded code signature sections")
    sigmeta = sigmeta[0]
    sig_offset = sigmeta[1].dataoff

    with open(filename, "rb") as f:
        # We need to account for the offset of the start of the binary itself because of Universal binaries
        f.seek(sig_offset + h.offset)
        sig_superblob = EmbeddedSignatureBlob()
        sig_superblob.deserialize(f)

        assert sig_superblob.code_dir_blob
        assert sig_superblob.sig_blob

        f.seek(h.offset)
        _validate_code_hashes(f, sig_superblob.code_dir_blob)

    assert sig_superblob.code_dir_blob.hash_type
    content_dir = os.path.split(os.path.split(os.path.abspath(filename))[0])[0]

    if sig_superblob.code_dir_blob.res_dir_hash:
        res_dir_path = os.path.join(content_dir, "_CodeSignature", "CodeResources")
        _validate_file_hash(
            res_dir_path,
            sig_superblob.code_dir_blob.res_dir_hash,
            sig_superblob.code_dir_blob.hash_type,
        )

    if sig_superblob.code_dir_blob.info_hash:
        info_file_path = os.path.join(content_dir, "Info.plist")
        _validate_file_hash(
            info_file_path,
            sig_superblob.code_dir_blob.info_hash,
            sig_superblob.code_dir_blob.hash_type,
        )

    if sig_superblob.code_dir_blob.reqs_hash:
        assert sig_superblob.reqs_blob
        _validate_blob_hash(
            sig_superblob.reqs_blob,
            sig_superblob.code_dir_blob.reqs_hash,
            sig_superblob.code_dir_blob.hash_type,
        )

    if sig_superblob.code_dir_blob.ent_hash:
        assert sig_superblob.ent_blob
        _validate_blob_hash(
            sig_superblob.ent_blob,
            sig_superblob.code_dir_blob.ent_hash,
            sig_superblob.code_dir_blob.hash_type,
        )

    if sig_superblob.code_dir_blob.ent_der_hash:
        assert sig_superblob.ent_der_blob
        _validate_blob_hash(
            sig_superblob.ent_der_blob,
            sig_superblob.code_dir_blob.ent_der_hash,
            sig_superblob.code_dir_blob.hash_type,
        )

    if (
        sig_superblob.code_dir_blob.top_dir_hash
        or sig_superblob.code_dir_blob.rep_specific_hash
    ):
        raise Exception("Unsupported special slot hash types")

    _validate_cms_signature(
        sig_superblob.sig_blob,
        sig_superblob.code_dir_blob.get_hash(sig_superblob.code_dir_blob.hash_type),
    )


def verify_mach_o_signature(filename: str):
    bundle, filepath = get_bundle_exec(filename)
    m = macholib.MachO.MachO(filepath)

    # There may be multiple headers because it might be a universal binary
    # In that case, each architecture is essentially just another MachO binary inside of the
    # universal binary. So we verify the signature for each one.
    for header in m.headers:
        _verify_single(filepath, header)
