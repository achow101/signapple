from elfesteem.macho import MACHO, LC_CODE_SIGNATURE
from io import BytesIO

from .blobs import EmbeddedSignatureBlob
from .utils import get_bundle_exec, get_macho_list


def _dump_signature(s: BytesIO):
    sig_superblob = EmbeddedSignatureBlob()
    sig_superblob.deserialize(s)

    assert sig_superblob.code_dir_blob
    assert sig_superblob.sig_blob

    print(sig_superblob)


def _dump_single(filename: str, b: MACHO):
    # Get the offset of the signature from the header
    # It is under the LC_CODE_SIGNATURE command
    sigmeta = [cmd for cmd in b.load.lhlist if cmd.cmd == LC_CODE_SIGNATURE]
    if len(sigmeta) == 0:
        raise Exception("No embedded code signature sections")
    elif len(sigmeta) > 1:
        raise Exception("Multiple embedded code signature sections")
    sig_lc = sigmeta[0]
    sig_end = sig_lc.dataoff + sig_lc.datasize

    sig_data = b.pack()[sig_lc.dataoff : sig_end]
    v = BytesIO(sig_data)

    _dump_signature(v)


def dump_mach_o_signature(filename):
    bundle, filepath = get_bundle_exec(filename)
    with open(filepath, "rb") as f:
        macho = MACHO(f.read())

    for header in get_macho_list(macho):
        _dump_single(filepath, header)


def dump_sigfile(filename):
    with open(filename, "rb") as f:
        _dump_signature(f)
