# Code signing certificates

Mach-O binaries are signed using X.509 certificates which have a key usage of Code Signing.
These certificates are issued by Apple and signed with one of Apple's intermediate certificates.
The intermediate certificates are signed with one of Apple's four root certificates.
Information about Apple's Certificate Authorities can be found on [their website](https://www.apple.com/certificateauthority/).
A copy of all of Apple's certificates is available at `signapple/certs`.

## Getting a code signing certificate

Code signing certificates are only issued to developers in the Apple Developer Program.
To get a certificate, please consult developer program documentation.
It should also be possible to do it through XCode.

## Exporting the certificate and private key

To use the code signing certificate with `signapple`, the certificate must be exported.
The certificate should be accessible through the Keychain Access app.
Find the code signing certificate, Control click (or right click) it, and choose the option to export the certificate.
Export the certificate as Personal Information Exchange file (`.p12` extension).

## Using the certificate and private key

Only the `sign` command uses the certificate and private key.
The path to the `.p12` file is specified on the command line as the second required argument.
Currently `signapple` can only handle files that are password protected.
When the private key is being a loaded, you will be prompted for your password.
Alternatively, the password can be passed in on the command line using the `-p` option, however this will expose the password in plaintext and leave it in command line history.
