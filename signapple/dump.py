from elfesteem.macho import (
    MACHO,
    LC_CODE_SIGNATURE,
    CPU_TYPE_I386,
    CPU_TYPE_X86_64,
    CPU_TYPE_ARM,
    CPU_TYPE_ARM64,
)
from io import BytesIO

from .blobs import EmbeddedSignatureBlob
from .utils import get_bundle_exec, get_macho_list


def _dump_signature(s: BytesIO):
    sig_superblob = EmbeddedSignatureBlob()
    sig_superblob.deserialize(s)

    assert sig_superblob.code_dir_blob
    assert sig_superblob.sig_blob

    print(sig_superblob)


def get_code_sig(b: MACHO):
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
    return BytesIO(sig_data)


def _dump_single(filename: str, b: MACHO):
    v = get_code_sig(b)
    _dump_signature(v)


def dump_mach_o_signature(filename):
    bundle, filepath = get_bundle_exec(filename)
    with open(filepath, "rb") as f:
        macho = MACHO(f.read(), parseSymbols=False)

    for header in get_macho_list(macho):
        _dump_single(filepath, header)


def dump_sigfile(filename):
    with open(filename, "rb") as f:
        _dump_signature(f)


def _get_cpu_type_string(cpu_type):
    if cpu_type == CPU_TYPE_I386:
        return "i386"
    elif cpu_type == CPU_TYPE_X86_64:
        return "x86_64"
    elif cpu_type == CPU_TYPE_ARM:
        return "arm32"
    elif cpu_type == CPU_TYPE_ARM64:
        return "arm64"


def get_binary_info(filename):
    with open(filename, "rb") as f:
        macho = MACHO(f.read(), parseSymbols=False)

    if hasattr(macho, "Fhdr"):
        print("Universal Binary")

    for header in get_macho_list(macho):
        print(f"{_get_cpu_type_string(header.Mhdr.cputype)} Executable")
        try:
            v = get_code_sig(header)
            print("Has code signature")
        except Exception as e:
            print(str(e))
