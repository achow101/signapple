import boto3
import base64
import datetime
import hashlib
import hmac
import json
import jwt
import os
import plistlib
import shutil
import time

from elfesteem.macho import MACHO
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


def notarize_bundle(
    bundle_path: str,
    api_privkey_file: str,
    issuer_id: str,
    file_list: Optional[str] = None,
    detach_target: Optional[str] = None,
):
    # Assume the file is named <foo>_AuthKey_<keyid>.p8 and retrieve the keyid
    privkey_name, ext = os.path.splitext(api_privkey_file)
    if ext != ".p8" or "AuthKey_" not in api_privkey_file:
        raise Exception("App Store Connect API Private key file not named as expected.")
    key_id = privkey_name.split("_")[-1]

    # Get the privkey
    with open(api_privkey_file, "r") as f:
        api_privkey = f.read().strip()

    # Verify bundle path
    bundle, binpath = get_bundle_exec(bundle_path)
    assert bundle is not None

    # ZIP the bundle
    zipped_bundle = shutil.make_archive(
        bundle,
        "zip",
        root_dir=os.path.dirname(bundle),
        base_dir=os.path.basename(bundle),
    )

    # Get time
    current_time = datetime.datetime.now()
    unix_timestamp = int(current_time.timestamp())
    iso_timestamp = current_time.strftime("%Y%m%dT%H%M%SZ")
    iso_date = current_time.strftime("%Y%m%d")

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
    api_token = jwt.encode(jwt_payload, api_privkey, "ES256", jwt_header)
    # print(api_token)

    # Hash the file with SHA256
    bundle_hash = hash_file(zipped_bundle, 2).hex()

    # Begin notarization process
    notary_headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    notary_data = {
        "submissionName": os.path.basename(zipped_bundle),
        "sha256": bundle_hash,
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

    aws_info = notary_resp["data"]["attributes"]
    bucket = aws_info["bucket"]
    obj = aws_info["object"]
    id = notary_resp["data"]["id"]

    print(f"Notarization ID: {id}")

    # Upload with boto
    s3 = boto3.client(
        "s3",
        aws_access_key_id=aws_info["awsAccessKeyId"],
        aws_secret_access_key=aws_info["awsSecretAccessKey"],
        aws_session_token=aws_info["awsSessionToken"],
    )

    print("Uploading...")
    resp = s3.upload_file(zipped_bundle, bucket, obj)

    # Poll submission status, wait for "Accepted"
    while True:
        headers = {"Authorization": f"Bearer {api_token}"}
        r = urlopen(Request(f"{NOTARY_SERVICE}/{id}", headers=headers, method="GET"))
        resp = json.loads(r.read())
        if resp["data"]["attributes"]["status"] == "Accepted":
            break
        time.sleep(5)
        print("Polling notarization status")

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
