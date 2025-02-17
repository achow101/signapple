# MacOS code signing and verification

`signapple` is a Python tool for creating, verifying, and inspecting signatures in Mach-O binaries.

It is currently targeted towards MacOS applications, however may be used with varying degrees of success for Mach-O binaries targeting other Apple operating systems.
Support for those is planned in the future.

## Installation

`signapple` can be installed from source using `pip install -e .` or with [poetry](https://python-poetry.org/) using `poetry install`.
This will add a command named `signapple`.
Additionally, once all of the dependencies are installed, `codesign.py` will provide the same capabilities as the `signapple` command.

### Dependencies

If you want to install dependencies manually, the dependencies are:
* [asn1crypto](https://github.com/wbond/asn1crypto/) - Certificate and CMS parsing
* [oscrypto](https://github.com/wbond/oscrypto/) - Cryptographic signature creation and verification
* [elfesteem](https://github.com/LRGH/elfesteem) - Mach-O binary manipulation.
* [certvalidator](https://github.com/achow101/certvalidator/tree/allow-more-criticals) - Certificate chain validation. Note that this is a specifically modified version to allow for Apple specific extensions.

## Usage

`signapple` has five commands: `verify`, `sign`, `dump`, `info`, and `notarize`.
`verify` will verify any existing code signatures.
`sign` will create a new code signature.
`dump` will print out information about existing code signatures.
`info` will print out information about an app bundle or binary.
`notarize` will submit an App bundle to Apple to be notarized and the notarization downloaded and stapled to the bundle.

Any paths can be either to the bundle directory or to the binary itself.

The full usage is as follows:

```sh
$ signapple --help
usage: signapple [-h] {verify,sign,dump,apply,info,notarize} ...

Signs and verifies MacOS code signatures

positional arguments:
  {verify,sign,dump,apply,info,notarize}
                        Commands
    verify              Verify the code signature for a binary
    sign                Create a code signature for a binary
    dump                Dump the code signature for a binary
    apply               Apply a detached signature
    info                Get information about the binary
    notarize            Notarize a signed app bundle and staple the notarization

options:
  -h, --help            show this help message and exit
```

```sh
$ signapple verify --help
usage: signapple verify [-h] filename

positional arguments:
  filename    Path to the binary to verify

options:
  -h, --help  show this help message and exit
```

```sh
$ signapple sign --help
usage: signapple sign [-h] [--passphrase PASSPHRASE] [--force] [--file-list FILE_LIST] [--detach DETACH] [--no-verify] [--hardened-runtime] keypath filename

positional arguments:
  keypath               Path to the PKCS#12 archive containing the certificate and private key to sign with
  filename              Path to the binary to sign. It will be modified in place

options:
  -h, --help            show this help message and exit
  --passphrase PASSPHRASE, -p PASSPHRASE
                        The passphrase protecting the private key. If not specified, you will be prompted to enter it later
  --force, -f           Ignore existing signatures. Otherwise if an existing signature is found, no signing will occur
  --file-list FILE_LIST
                        Path to write out the list of modified files to
  --detach DETACH       Detach the signature and write it to this path
  --no-verify           Don't verify the signature after creating.
  --hardened-runtime    Enable Hardened Runtime feature for this binary
```

```sh
$ signapple dump --help
usage: signapple dump [-h] [--sigfile] filename

positional arguments:
  filename    Path to the binary to dump

options:
  -h, --help  show this help message and exit
  --sigfile   The path is to a detached signature file produced by 'sign --detach' rather than a signed binary
```

```sh
$ signapple apply --help
usage: signapple apply [-h] [--no-verify] filename sig

positional arguments:
  filename     The binary to attach the signature to
  sig          The detached signature. Either a bundle's detached signature directory or the signature file itself

options:
  -h, --help   show this help message and exit
  --no-verify  Don't verify the signature after attaching
```

```sh
$ signapple info --help
usage: signapple info [-h] filename

positional arguments:
  filename    The binary (or bundle) to get information about

options:
  -h, --help  show this help message and exit
```

```sh
$ signapple notarize --help
usage: signapple notarize [-h] [--file-list FILE_LIST] [--detach DETACH] [--staple-only] apikeyfile issuer_id bundle

positional arguments:
  apikeyfile            Path to the API private key file downloaded from App Store Connect
  issuer_id             App Store Connect Issuer ID
  bundle                Path to the signed app bundle to notarize. It will be modified in place

options:
  -h, --help            show this help message and exit
  --file-list FILE_LIST
                        Path to write out the list of modified files to
  --detach DETACH       Detach the notarization and write it to this path
  --staple-only         Only look up and staple the notarization if it exists
```

## Signing certificates

In order to sign, you must have a signing certificate.
This is obtained from Apple.
These certificates can then be exported as PKCS#12 files to be used with `signapple`.
Please read the [documentation](docs/certificates.md) for more information about certificates.

## Detached signatures

The detached signatures that `signapple` creates are not the same detached signatures that Apple's `codesign` creates.
Instead these detached signatures are intended to be attached to the original unsigned binary at a later date.
The signatures will be placed into the target directory with a directory structure that mirrors the structure of the original application bundle.
Any generated files (such as `Contents/_CodeSignature/CodeResources`) will be found there.
The signatures will just be the embedded signature with saved in a file that has the same name as the original binary but with an extension of the format `.<arch>sign` where `<arch>` is the name of the machine architecture for that signed binary.
In the case of universal binaries, there will multiple such signatures.
Typically there will be `.x86_64sign` and `.arm64sign` files for universal binaries.

## Notarization

In order to notarize an app bundle, you must have an App Store Connect API Private key downloaded from Apple, and the UUID of your Apple Developer Team.
Please read the [documentation](docs/notarization.md) for more information about notarization.

## License

This project is available under the MIT License. See [LICENSE](LICENSE) for more information. Copyright(c) 2020 Andrew Chow.
