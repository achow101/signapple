import os

from oscrypto.asymmetric import load_certificate

# Information about Apple's certificates and policies can be found at https://www.apple.com/certificateauthority/
APPLE_ROOTS = [
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleComputerRootCertificate.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleIncRootCertificate.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleRootCA-G2.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleRootCA-G3.cer")).asn1,
]

APPLE_INTERMEDIATES = [
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleISTCA2G1.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleISTCA8G1.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleAAI2CA.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleAAICA.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleAAICAG3.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleApplicationIntegrationCA5G1.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/DevAuthCA.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/DeveloperIDCA.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleSoftwareUpdateCertificationAuthority.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleTimestampCA.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleWWDRCAG2.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleWWDRCAG3.cer")).asn1,
    load_certificate(os.path.join(os.path.dirname(__file__), "certs/AppleWWDRCA.cer")).asn1,
]
