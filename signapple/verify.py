import io
import macholib  # type: ignore
import os

from asn1crypto.cms import CMSAttributes  # type: ignore
from certvalidator.context import ValidationContext  # type: ignore
from certvalidator import CertificateValidator  # type: ignore
from macholib.MachO import MachO, MachOHeader  # type: ignore
from macholib.mach_o import LC_CODE_SIGNATURE  # type: ignore
from oscrypto import asymmetric  # type: ignore
from typing import BinaryIO

from .blobs import (
    Blob,
    CodeDirectoryBlob,
    EmbeddedSignatureBlob,
    SignatureBlob,
    RequirementsBlob,
)
from .utils import get_hash, hash_file, sread

# Information about Apple's certificates and policies can be found at https://www.apple.com/certificateauthority/
APPLE_ROOT_CERT = b'0\x82\x04\xbb0\x82\x03\xa3\xa0\x03\x02\x01\x02\x02\x01\x020\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000b1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nApple Inc.1&0$\x06\x03U\x04\x0b\x13\x1dApple Certification Authority1\x160\x14\x06\x03U\x04\x03\x13\rApple Root CA0\x1e\x17\r060425214036Z\x17\r350209214036Z0b1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nApple Inc.1&0$\x06\x03U\x04\x0b\x13\x1dApple Certification Authority1\x160\x14\x06\x03U\x04\x03\x13\rApple Root CA0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xe4\x91\xa9\t\x1f\x91\xdb\x1eGP\xeb\x05\xed^y\x84-\xeb6\xa2WLU\xec\x8b\x19\x89\xde\xf9Kl\xf5\x07\xab"0\x02\xe8\x18>\xf8P\t\xd3\x7fA\xa8\x98\xf9\xd1\xcaf\x9c$k\x11\xd0\xa3\xbb\xe4\x1b*\xc3\x1f\x95\x9ez\x0c\xa4G\x8b[\xd4\x1673\xcb\xc4\x0fM\xce\x14i\xd1\xc9\x19r\xf5]\x0e\xd5\x7f_\x9b\xf2%\x03\xbaU\x8fM]\r\xf1d5#\x15K\x15Y\x1d\xb3\x94\xf7\xf6\x9c\x9e\xcfP\xba\xc1XPg\x8f\x08\xb4 \xf7\xcb\xac, op\xb6?\x010\x8c\xb7C\xcf\x0f\x9d=\xf3+I(\x1a\xc8\xfe\xce\xb5\xb9\x0e\xd9^\x1c\xd6\xcb=\xb5:\xad\xf4\x0f\x0e\x00\x92\x0b\xb1!\x16.t\xd5<\r\xdbb\x16\xab\xa3q\x92GSU\xc1\xaf/A\xb3\xf8\xfb\xe3p\xcd\xe6\xa3LE~\x1fLkP\x96A\x89\xc4tb\x0b\x10\x83A\x873\x8a\x81\xb10X\xecZ\x042\x8ch\xb3\x8f\x1d\xdees\xffg^e\xbcI\xd8v\x9f3\x14e\xa1w\x94\xc9-\x02\x03\x01\x00\x01\xa3\x82\x01z0\x82\x01v0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x060\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14+\xd0iG\x94v\t\xfe\xf4k\x8d.@\xa6\xf7GM\x7f\x08^0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14+\xd0iG\x94v\t\xfe\xf4k\x8d.@\xa6\xf7GM\x7f\x08^0\x82\x01\x11\x06\x03U\x1d \x04\x82\x01\x080\x82\x01\x040\x82\x01\x00\x06\t*\x86H\x86\xf7cd\x05\x010\x81\xf20*\x06\x08+\x06\x01\x05\x05\x07\x02\x01\x16\x1ehttps://www.apple.com/appleca/0\x81\xc3\x06\x08+\x06\x01\x05\x05\x07\x02\x020\x81\xb6\x1a\x81\xb3Reliance on this certificate by any party assumes acceptance of the then applicable standard terms and conditions of use, certificate policy and certification practice statements.0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\\6\x99L-x\xb7\xed\x8c\x9b\xdc\xf3w\x9b\xf2v\xd2w0O\xc1\x1f\x85\x83\x85\x1b\x99=G7\xf2\xa9\x9b@\x8e,\xd4\xb1\x90\x12\xd8\xbe\xf4s\x9b\xee\xd2d\x0f\xcbyO4\xd8\xa2>\xf9x\xffk\xc8\x07\xec}9\x83\x8bS \xd38\xc4\xb1\xbf\x9aO\nk\xff+\xfcY\xa7\x05\t|\x17@V\x11\x1et\xd3\xb7\x8b#;G\xa3\xd5o$\xe2\xeb\xd1\xb7p\xdf\x0fE\xe1\'\xca\xf1mx\xed\xe7\xb5\x17\x17\xa8\xdc~"5\xca%\xd5\xd9\x0f\xd6k\xd4\xa2$#\x11\xf7\xa1\xac\x8fs\x81`\xc6\x1b[\t/\x92\xb2\xf8DH\xf0`8\x9e\x15\xf5=&g \x8a3j\xf7\r\x82\xcf\xde\xeb\xa3/\xf9Sj[d\xc0c3w\xf7:\x07,V\xeb\xda\x0f!\x0e\xda\xbas\x19O\xb5\xd96\x7f\xc1\x87U\xd9\xa7\x99\xb92B\xfb\xd8\xd5q\x9e~\xa1R\xb7\x1b\xbd\x93B$\x12*\xc7\x0f\x1d\xb6M\x9c^c\xc8K\x80\x17P\xaa\x8a\xd5\xda\xe4\xfc\xd0\t\x077\xb0uu!'


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
    # Check the hash of CodeDirectory matches what is in the signature
    message_digest = None
    for attr in sig_blob.signed_attrs:
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
        trust_roots=[APPLE_ROOT_CERT],
        allow_fetching=False,
        additional_critical_extensions=APPLE_CERT_CRIT_EXTS,
    )
    validator = CertificateValidator(
        sig_blob.cert_chain[-1], sig_blob.cert_chain[0:-1], validation_context
    )
    validator.validate_usage({"digital_signature"}, {"code_signing"})

    # Check the signature
    pubkey = asymmetric.load_public_key(sig_blob.cert_chain[-1].public_key)
    signed_msg = _sort_attributes(sig_blob.signed_attrs).dump()
    asymmetric.rsa_pkcs1v15_verify(
        pubkey, sig_blob.sig, signed_msg, sig_blob.digest_alg
    )


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
    m = macholib.MachO.MachO(filename)

    # There may be multiple headers because it might be a universal binary
    # In that case, each architecture is essentially just another MachO binary inside of the
    # universal binary. So we verify the signature for each one.
    for header in m.headers:
        _verify_single(filename, header)
