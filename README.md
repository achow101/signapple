# MacOS code signing and verification

`signapple` is a Python tool for creating, verifying, and inspecting signatures in Mach-O binaries.

It is currently targeted towards MacOS applications, however may be used with varying degrees of success for Mach-O binaries targeting other Apple operating systems.
Support for those is planned in the future.

## Installation

`signapple` can be installed from source using `pip install -e .` or with [poetry](https://python-poetry.org/) using `poetry install`.
This will add a command named `signapple`.
Additionally, once all of the dependencies are installed, `codesign.py` will provide the same capabilities as the `signapple` command.

## Usage

`signapple` has three commands: `verify`, `sign`, and `dump`.
`verify` will verify any existing code signatures.
`sign` will create a new code signature.
`dump` will print out information about existing code signatures.

Any paths can be either to the bundle directory or to the binary itself.

The full usage is as follows:
```
$ signapple --help
usage: signapple [-h] {verify,sign,dump} ...

Signs and verifies MacOS code signatures

positional arguments:
  {verify,sign,dump}  Commands
    verify            Verify the code signature for a binary
    sign              Create a code signature for a binary
    dump              Dump the code signature for a binary

optional arguments:
  -h, --help          show this help message and exit

$ signapple verify --help
usage: signapple verify [-h] filename

positional arguments:
  filename    Path to the binary to verify

optional arguments:
  -h, --help  show this help message and exit

$ signapple sign --help
usage: signapple sign [-h] [--passphrase PASSPHRASE] [--force] [--file-list FILE_LIST] keypath filename

positional arguments:
  keypath               Path to the PKCS#12 archive containing the certificate and private key to sign with
  filename              Path to the binary to sign. It will be modified in place

optional arguments:
  -h, --help            show this help message and exit
  --passphrase PASSPHRASE, -p PASSPHRASE
                        The passphrase protecting the private key. If not specified, you will be prompted to enter it later
  --force, -f           Ignore existing signatures. Otherwise if an existing signature is found, no signing will occur
  --file-list FILE_LIST
                        Path to write out the list of modified files to
$  signapple dump --help
usage: signapple dump [-h] filename

positional arguments:
  filename    Path to the binary to dump

optional arguments:
  -h, --help  show this help message and exit
```

## Signing certificates

In order to sign, you must have a signing certificate.
This is obtained from Apple.
These certificates can then be exported as PKCS#12 files to be used with `signapple`.
Please read the [documentation](docs/certificates.md) for more information about certificates.

## License

This project is available under the MIT License. See [LICENSE](LICENSE) for more information. Copyright(c) 2020 Andrew Chow.
