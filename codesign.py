#! /usr/bin/env python3

import argparse

parser = argparse.ArgumentParser(description="Signs and verifies MacOS code signatures")

subparsers = parser.add_subparsers(help="Commands")

verify_subparser = subparsers.add_subparser(
    "verify", help="Verify the code signature for a binary"
)
verify_subparser.add_argument("filename", help="Path to the binary to verify")

args = parser.parse_args()
