import argparse


from .dump import dump_mach_o_signature
from .verify import verify_mach_o_signature
from .sign import apply_sig, sign_mach_o


def verify(args):
    verify_mach_o_signature(args.filename)
    print("Code signature is valid")


def sign(args):
    sign_mach_o(
        args.filename,
        args.keypath,
        args.passphrase,
        args.force,
        args.file_list,
        args.detach,
    )
    print("Code signature created")
    if args.verify and not args.detach:
        verify(args)


def dump(args):
    dump_mach_o_signature(args.filename)


def apply(args):
    apply_sig(args.filename, args.sig)
    print("Code signature applied")
    if args.verify:
        verify(args)


def main():
    parser = argparse.ArgumentParser(
        description="Signs and verifies MacOS code signatures"
    )

    subparsers = parser.add_subparsers(help="Commands", dest="command", required=True)

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
    sign_subparser.set_defaults(func=sign)

    dump_subparser = subparsers.add_parser(
        "dump", help="Dump the code signature for a binary"
    )
    dump_subparser.add_argument("filename", help="Path to the binary to dump")
    dump_subparser.set_defaults(func=dump)

    apply_subparser = subparsers.add_parser("apply", help="Apply a detached signature")
    apply_subparser.add_argument(
        "--no-verify",
        help="Don't verify the signature after attaching",
        action="store_false",
        dest="verify",
    )
    apply_subparser.add_argument("filename", help="The binary to attach the signature to")
    apply_subparser.add_argument(
        "sig",
        help="The directory containing the detached signature. The same path that was given to --detach during signing",
    )
    apply_subparser.set_defaults(func=apply)

    args = parser.parse_args()
    args.func(args)
