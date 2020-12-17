import argparse


from .verify import verify_mach_o_signature


def verify(args):
    verify_mach_o_signature(args.filename)
    print("Code signature is valid")


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

    args = parser.parse_args()
    args.func(args)
