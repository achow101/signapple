import argparse


from .dump import dump_mach_o_signature, dump_sigfile, get_binary_info
from .notarize import notarize_bundle
from .sign import apply_sig, sign_macos_app, SigningStatus
from .verify import verify_mach_o_signature


def verify(args):
    verify_mach_o_signature(args.filename)
    print("Code signature is valid")


def sign(args):
    sign_macos_app(
        args.filename,
        args.keypath,
        args.passphrase,
        args.force,
        args.file_list,
        args.detach,
        args.hardened_runtime,
    )
    print("Code signature created")
    if args.verify and not args.detach:
        verify(args)


def dump(args):
    if args.sigfile:
        dump_sigfile(args.filename)
    else:
        dump_mach_o_signature(args.filename)


def apply(args):
    ret = apply_sig(args.filename, args.sig)
    if ret == SigningStatus.OK:
        print("Code signature applied")
        if args.verify:
            verify(args)
    elif ret == SigningStatus.FAIL:
        print("Failed to apply code signature")
    elif ret == SigningStatus.SOME_OK:
        print("Some code signatures applied")
    else:
        assert False


def notarize(args):
    notarize_bundle(
        args.bundle, args.apikeyfile, args.issuer_id, args.file_list, args.detach, args.staple_only
    )


def bininfo(args):
    get_binary_info(args.filename)


def main():
    parser = argparse.ArgumentParser(
        description="Signs and verifies MacOS code signatures"
    )

    subparsers = parser.add_subparsers(help="Commands", dest="command")
    # Python >=3.7 has a required karg in add_subparsers. But since we need to support 3.6, this hack is the only way
    subparsers.required = True

    verify_subparser = subparsers.add_parser(
        "verify", help="Verify the code signature for a binary"
    )
    verify_subparser.add_argument("filename", help="Path to the binary to verify")
    verify_subparser.set_defaults(func=verify)

    sign_subparser = subparsers.add_parser(
        "sign", help="Create a code signature for a binary"
    )
    sign_subparser.add_argument(
        "keypath",
        help="Path to the PKCS#12 archive containing the certificate and private key to sign with",
    )
    sign_subparser.add_argument(
        "filename", help="Path to the binary to sign. It will be modified in place"
    )
    sign_subparser.add_argument(
        "--passphrase",
        "-p",
        help="The passphrase protecting the private key. If not specified, you will be prompted to enter it later",
    )
    sign_subparser.add_argument(
        "--force",
        "-f",
        help="Ignore existing signatures. Otherwise if an existing signature is found, no signing will occur",
        action="store_true",
    )
    sign_subparser.add_argument(
        "--file-list", help="Path to write out the list of modified files to"
    )
    sign_subparser.add_argument(
        "--detach", help="Detach the signature and write it to this path"
    )
    sign_subparser.add_argument(
        "--no-verify",
        help="Don't verify the signature after creating.",
        action="store_false",
        dest="verify",
    )
    sign_subparser.add_argument(
        "--hardened-runtime",
        help="Enable Hardened Runtime feature for this binary",
        action="store_true",
    )
    sign_subparser.set_defaults(func=sign)

    dump_subparser = subparsers.add_parser(
        "dump", help="Dump the code signature for a binary"
    )
    dump_subparser.add_argument("filename", help="Path to the binary to dump")
    dump_subparser.add_argument(
        "--sigfile",
        help="The path is to a detached signature file produced by 'sign --detach' rather than a signed binary",
        action="store_true",
    )
    dump_subparser.set_defaults(func=dump)

    apply_subparser = subparsers.add_parser("apply", help="Apply a detached signature")
    apply_subparser.add_argument(
        "--no-verify",
        help="Don't verify the signature after attaching",
        action="store_false",
        dest="verify",
    )
    apply_subparser.add_argument(
        "filename", help="The binary to attach the signature to"
    )
    apply_subparser.add_argument(
        "sig",
        help="The directory containing the detached signature. The same path that was given to --detach during signing",
    )
    apply_subparser.set_defaults(func=apply)

    info_subparser = subparsers.add_parser(
        "info", help="Get information about the binary"
    )
    info_subparser.add_argument(
        "filename", help="The binary (or bundle) to get information about"
    )
    info_subparser.set_defaults(func=bininfo)

    notarize_subparser = subparsers.add_parser(
        "notarize", help="Notarize a signed app bundle and staple the notarization"
    )
    notarize_subparser.add_argument(
        "apikeyfile",
        help="Path to the API private key file downloaded from App Store Connect",
    )
    notarize_subparser.add_argument(
        "issuer_id",
        help="App Store Connect Issuer ID",
    )
    notarize_subparser.add_argument(
        "bundle",
        help="Path to the signed app bundle to notarize. It will be modified in place",
    )
    notarize_subparser.add_argument(
        "--file-list", help="Path to write out the list of modified files to"
    )
    notarize_subparser.add_argument(
        "--detach", help="Detach the notarization and write it to this path"
    )
    notarize_subparser.add_argument(
        "--staple-only", help="Only look up and staple the notarization if it exists",
        action="store_true",
    )
    notarize_subparser.set_defaults(func=notarize)

    args = parser.parse_args()
    args.func(args)
