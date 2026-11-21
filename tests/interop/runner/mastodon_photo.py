"""Publish a Photos post and verify Mastodon's cached image and preview."""

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from interop import ACTIVITY_JSON, Browser, UnspokenControl, requireStatus


def publish():
    unspoken = UnspokenControl(os.environ["UNSPOKEN_URL"],
                               os.environ["FAKE_OIDC_URL"])
    unspoken.login("alice")
    post_id = unspoken.createPostWithAttachment(
        "alice", {"post_kind": "photo", "content": "AVIF federation test"},
        "landscape.png", Path("/runner/landscape.png").read_bytes(),
        "image/png")
    uri = f"{unspoken.base_url}/p/{post_id}"
    response = Browser().get(uri, {"Accept": ACTIVITY_JSON})
    requireStatus(response, 200, "fetch Unspoken ActivityPub photo")
    attachments = json.loads(response.body)["attachment"]
    if len(attachments) != 1 or attachments[0]["mediaType"] != "image/avif":
        raise RuntimeError(f"Expected one federated AVIF: {attachments}")

    with urlopen(attachments[0]["url"], timeout=10) as media:
        if (media.headers.get_content_type() != "image/avif"
                or media.read(12)[4:] != b"ftypavif"):
            raise RuntimeError("Unspoken did not serve AVIF bytes")
    print(uri)


def verify(status_id, post_uri):
    mastodon_url = os.environ["MASTODON_URL"]
    mastodon_host = urlsplit(mastodon_url).hostname
    headers = {"Host": mastodon_host, "X-Forwarded-Proto": "https"}
    result = Browser().get(f"{mastodon_url}/api/v1/statuses/{status_id}",
                           headers)
    requireStatus(result, 200, "fetch imported status from Mastodon REST API")
    status = json.loads(result.body)
    attachments = status["media_attachments"]
    if status["uri"] != post_uri or len(attachments) != 1:
        raise RuntimeError(f"Unexpected Mastodon status {status_id}: {status}")

    attachment = attachments[0]
    if attachment["type"] != "image":
        raise RuntimeError(f"Mastodon did not process AVIF: {attachment}")
    for field in ("url", "preview_url"):
        media_url = urlsplit(attachment.get(field) or "")
        if media_url.hostname != mastodon_host:
            raise RuntimeError(f"Expected Mastodon to serve {field}: "
                               f"{attachment}")
        if media_url.path.startswith("/media_proxy/"):
            raise RuntimeError(f"Mastodon status {status_id} has no cached "
                               f"{field} for {post_uri}: {media_url.geturl()}")
        local_url = mastodon_url + media_url.path
        with urlopen(Request(local_url, headers=headers), timeout=10) as media:
            if (media.headers.get_content_type() != "image/jpeg"
                    or media.read(3) != b"\xff\xd8\xff"):
                raise RuntimeError(f"Mastodon {field} did not serve JPEG")
    print(f"{post_uri} → Mastodon status {status_id} (JPEG image and preview)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("publish")
    verify_parser = modes.add_parser("verify")
    verify_parser.add_argument("status_id")
    verify_parser.add_argument("post_uri")
    args = parser.parse_args()
    if args.mode == "publish":
        publish()
    else:
        verify(args.status_id, args.post_uri)
