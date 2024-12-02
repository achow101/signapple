import base64
import datetime
import getpass
import hashlib
import hmac
import json
import os
import plistlib
import shutil
import time

from elfesteem.macho import MACHO
from asn1crypto.algos import DSASignature
from oscrypto.asymmetric import load_private_key, ecdsa_sign
from oscrypto.keys import parse_private
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote
from typing import Optional

from .blobs import EmbeddedSignatureBlob
from .dump import get_code_sig
from .utils import (
    get_bundle_exec,
    get_macho_list,
    hash_file,
)

NOTARY_SERVICE = "https://appstoreconnect.apple.com/notary/v2/submissions"
TICKET_LOOKUP = "https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup"


def _get_app_store_connect_token(
    api_privkey_file: str,
    issuer_id: str,
    current_time: datetime.datetime,
    passphrase: Optional[str] = None,
):
    # Assume the file is named <foo>_AuthKey_<keyid>.p8 and retrieve the keyid
    privkey_name, ext = os.path.splitext(api_privkey_file)
    if ext != ".p8" or "AuthKey_" not in api_privkey_file:
        raise Exception("App Store Connect API Private key file not named as expected.")
    key_id = privkey_name.split("_")[-1]

    if passphrase is None:
        passphrase = getpass.getpass(f"Enter the passphrase for {api_privkey_file}:")
    pass_bytes = passphrase.encode()

    # Get the privkey
    with open(api_privkey_file, "rb") as f:
        privkey = load_private_key(parse_private(f.read(), pass_bytes))

    unix_timestamp = int(current_time.timestamp())

    # Make JSON Web Token
    jwt_header = {
        "alg": "ES256",
        "kid": key_id,
        "typ": "JWT",
    }
    jwt_payload = {
        "iss": issuer_id,
        "iat": unix_timestamp,
        "exp": unix_timestamp + 900,  # 15 minutes
        "aud": "appstoreconnect-v1",
        "scope": [
            "GET /notary/v2/submissions",
            "POST /notary/v2/submissions",
        ],
    }
    jwt_header_b64 = base64.urlsafe_b64encode(json.dumps(jwt_header).encode()).strip(
        b"="
    )
    jwt_payload_b64 = base64.urlsafe_b64encode(json.dumps(jwt_payload).encode()).strip(
        b"="
    )
    token_unsigned = jwt_header_b64 + b"." + jwt_payload_b64

    # ecdsa_sign produces DER encoded sigs. Parse and extract compact, which `to_p1363()` seems to do
    sig = ecdsa_sign(privkey, token_unsigned, "sha256")
    dsa_sig = DSASignature().load(sig)
    sig_b64 = base64.urlsafe_b64encode(dsa_sig.to_p1363()).strip(b"=")

    token = token_unsigned + b"." + sig_b64
    return token.decode()


def _begin_notarization(api_token, filename: str, file_hash: str):
    notary_headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    notary_data = {
        "submissionName": filename,
        "sha256": file_hash,
    }
    resp = urlopen(
        Request(
            NOTARY_SERVICE,
            data=json.dumps(notary_data).encode(),
            headers=notary_headers,
            method="POST",
        )
    )
    notary_resp = json.loads(resp.read())
    return notary_resp["data"]["id"], notary_resp["data"]["attributes"]


def _s3_upload(
    filename: str,
    aws_bucket: str,
    aws_obj: str,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_session_token: str,
    file_hash: str,
    current_time: datetime.datetime,
):
    iso_timestamp = current_time.strftime("%Y%m%dT%H%M%SZ")
    iso_date = current_time.strftime("%Y%m%d")

    # Build AWS signature. See https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    host = f"{aws_bucket}.s3-accelerate.amazonaws.com"
    http_method = "PUT"
    uri = f"/{aws_obj}"
    hashed_payload = file_hash
    aws_headers = {
        "Host": host,
        "x-amz-content-sha256": hashed_payload,
        "x-amz-security-token": aws_session_token,
        "x-amz-date": iso_timestamp,
    }
    query_string = ""
    region = "us-west-2"
    scope = f"{iso_date}/{region}/s3/aws4_request"

    canon_headers = ""
    signed_headers = ""
    for key in sorted(aws_headers.keys()):
        value = aws_headers[key]
        canon_headers += key.lower() + ":" + value.strip() + "\n"
        signed_headers += key.lower() + ";"
    signed_headers = signed_headers[:-1]

    aws_canonical_req = f"{http_method}\n{quote(uri)}\n{quote(query_string)}\n{canon_headers}\n{signed_headers}\n{hashed_payload}"
    aws_str_to_sign = f"AWS4-HMAC-SHA256\n{iso_timestamp}\n{scope}\n{hashlib.sha256(aws_canonical_req.encode()).hexdigest()}"
    aws_date_key = hmac.new(
        key=f"AWS4{aws_secret_access_key}".encode(),
        msg=iso_date.encode(),
        digestmod=hashlib.sha256,
    ).digest()
    aws_date_region_key = hmac.new(
        key=aws_date_key, msg=region.encode(), digestmod=hashlib.sha256
    ).digest()
    aws_date_region_service_key = hmac.new(
        key=aws_date_region_key, msg=b"s3", digestmod=hashlib.sha256
    ).digest()
    aws_signing_key = hmac.new(
        key=aws_date_region_service_key, msg=b"aws4_request", digestmod=hashlib.sha256
    ).digest()
    aws_sig = hmac.new(
        key=aws_signing_key, msg=aws_str_to_sign.encode(), digestmod=hashlib.sha256
    ).hexdigest()

    # Upload file to AWS S3
    aws_cred = f"{aws_access_key_id}/{scope}"
    aws_headers[
        "Authorization"
    ] = f"AWS4-HMAC-SHA256 Credential={aws_cred},SignedHeaders={signed_headers},Signature={aws_sig}"

    with open(filename, "rb") as f:
        # Upload the file to S3 bucket specified in resp
        url = f"https://{host}{uri}"
        try:
            s3_resp = urlopen(
                Request(url, data=f.read(), headers=aws_headers, method="PUT")
            )
        except HTTPError as e:
            print(e.fp.read().decode())
            raise (e)


def _wait_submission_status(api_token: str, notarization_id: str):
    # Poll submission status, wait for no longer "In Progress"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    while True:
        r = urlopen(
            Request(
                f"{NOTARY_SERVICE}/{notarization_id}", headers=headers, method="GET"
            )
        )
        resp = json.loads(r.read())
        if resp["data"]["attributes"]["status"] != "In Progress":
            break
        time.sleep(5)
        print("Polling notarization status")

    # Error if invalid or rejected
    if resp["data"]["attributes"]["status"] in ["Invalid", "Rejected"]:
        print(f"Notarization was {resp['data']['attributes']['status']}")

        # Get the log for more info
        resp = urlopen(
            Request(
                f"{NOTARY_SERVICE}/{notarization_id}/logs",
                headers=headers,
                method="GET",
            )
        )
        notary_resp = json.loads(resp.read())
        logs_url = notary_resp["data"]["attributes"]["developerLogUrl"]
        resp = urlopen(Request(logs_url, method="GET"))
        print(resp.read().decode())

        raise Exception("Notarization failed")


def _staple_notarization(
    bundle: str,
    binpath: str,
    file_list: Optional[str] = None,
    detach_target: Optional[str] = None,
):
    # Get code directory hash from the main executable in the bundle
    with open(binpath, "rb") as f:
        macho = MACHO(f.read(), parseSymbols=False)
    sig = get_code_sig(get_macho_list(macho)[0])
    sig_superblob = EmbeddedSignatureBlob()
    sig_superblob.deserialize(sig)
    assert sig_superblob.code_dir_blob is not None
    assert sig_superblob.code_dir_blob.hash_type is not None
    code_dir_hash = sig_superblob.code_dir_blob.get_hash(
        sig_superblob.code_dir_blob.hash_type
    )[:20].hex()

    # Pull ticket from API and staple
    # ticket_record is of the form 2/<digest type>/<20 byte truncated code directory digest>
    ticket_record_name = f"2/{sig_superblob.code_dir_blob.hash_type}/{code_dir_hash}"
    ticket_lookup_data = {
        "records": [
            {
                "recordName": ticket_record_name,
            },
        ],
    }
    print("Stapling")
    resp = urlopen(
        Request(
            TICKET_LOOKUP,
            data=json.dumps(ticket_lookup_data).encode(),
            headers={},
            method="POST",
        )
    )
    ticket_resp = json.loads(resp.read())
    ticket_info = ticket_resp["records"][0]
    assert ticket_info["recordName"] == ticket_record_name
    if "serverErrorCode" in ticket_info:
        raise Exception(f"Unable to staple ticket. Error: {ticket_info}")
    ticket_b64 = ticket_info["fields"]["signedTicket"]["value"]
    ticket_data = base64.b64decode(ticket_b64)

    # Stapling is just outputting the ticket data to Contents/CodeResources
    if detach_target is not None:
        staple_path = os.path.join(
            detach_target, os.path.basename(bundle), "Contents", "CodeResources"
        )
    else:
        staple_path = os.path.join(bundle, "Contents", "CodeResources")
    os.makedirs(os.path.dirname(staple_path), exist_ok=True)
    with open(staple_path, "wb") as f:
        f.write(ticket_data)
    if file_list is not None:
        with open(file_list, "a") as f:
            f.write(staple_path + "\n")

    print("Notarization stapled to bundle")


def _submit_bundle_for_notarization(
    bundle: str,
    binpath: str,
    api_privkey_file: str,
    issuer_id: str,
    file_list: Optional[str] = None,
    detach_target: Optional[str] = None,
    passphrase: Optional[str] = None,
):
    # ZIP the bundle
    zipped_bundle = shutil.make_archive(
        bundle,
        "zip",
        root_dir=os.path.dirname(bundle),
        base_dir=os.path.basename(bundle),
    )

    # Get time
    current_time = datetime.datetime.now().astimezone(datetime.UTC)

    # Get App Store Connect API Token
    api_token = _get_app_store_connect_token(api_privkey_file, issuer_id, current_time, passphrase)
    # print(api_token)

    # Hash the file with SHA256
    bundle_hash = hash_file(zipped_bundle, 2).hex()

    # Begin notarization process
    id, aws_info = _begin_notarization(
        api_token, os.path.basename(zipped_bundle), bundle_hash
    )
    bucket = aws_info["bucket"]
    obj = aws_info["object"]

    print(f"Notarization ID: {id}")

    # Upload to S3 bucket
    print("Uploading...")
    _s3_upload(
        zipped_bundle,
        bucket,
        obj,
        aws_info["awsAccessKeyId"],
        aws_info["awsSecretAccessKey"],
        aws_info["awsSessionToken"],
        bundle_hash,
        current_time,
    )

    # Wait for notarization to be accepted
    _wait_submission_status(api_token, id)


def notarize_bundle(
    bundle_path: str,
    api_privkey_file: str,
    issuer_id: str,
    file_list: Optional[str] = None,
    detach_target: Optional[str] = None,
    staple_only: bool = False,
    passphrase: Optional[str] = None,
):
    # Verify bundle path
    bundle, binpath = get_bundle_exec(bundle_path)
    assert bundle is not None

    if not staple_only:
        _submit_bundle_for_notarization(
            bundle, binpath, api_privkey_file, issuer_id, file_list, detach_target, passphrase
        )

    _staple_notarization(bundle, binpath, file_list, detach_target)
