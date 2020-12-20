from macholib.MachO import MachO, MachOHeader
from macholib.mach_o import LC_CODE_SIGNATURE

from .blobs import EmbeddedSignatureBlob
from .utils import get_bundle_exec


def _dump_single(filename: str, h: MachOHeader):
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

    print(sig_superblob)


def dump_mach_o_signature(filename):
    bundle, filepath = get_bundle_exec(filename)
    macho = MachO(filepath)

    for header in macho.headers:
        _dump_single(filepath, header)
