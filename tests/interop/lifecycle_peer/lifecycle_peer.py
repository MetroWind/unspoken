#!/usr/bin/env python3

"""A controllable signed ActivityPub peer for lifecycle interop tests."""

import base64
import hashlib
import http.client
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


HOST = "lifecycle-peer.test"
PORT = 8090
BASE_URL = f"http://{HOST}:{PORT}"
ACTORS = {
    "main": "/actor",
    "transient": "/transient-actor",
}
keys: dict[str, list[tuple[Path, str]]] = {}
key_versions: dict[str, int] = {name: 0 for name in ACTORS}


def makeKeyPair(directory: Path, name: str, version: int) -> tuple[Path, str]:
    """Generate one RSA keypair and return its private path and public PEM."""
    private_key = directory / f"{name}-{version}.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
         "rsa_keygen_bits:2048", "-out", str(private_key)],
        check=True, capture_output=True)
    public_key = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout"],
        check=True, capture_output=True, text=True).stdout
    return private_key, public_key


def actorUri(name: str) -> str:
    """Return the canonical ActivityPub URI for one test actor."""
    return BASE_URL + ACTORS[name]


def actorDocument(name: str) -> dict[str, object]:
    """Return the currently active actor document for a test actor."""
    version = key_versions[name]
    _, public_key = keys[name][version]
    uri = actorUri(name)
    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": uri,
        "type": "Person",
        "preferredUsername": f"lifecycle-{name}",
        "name": f"Lifecycle {name}",
        "inbox": BASE_URL + "/inbox",
        "publicKey": {
            "id": f"{uri}#key-{version + 1}",
            "owner": uri,
            "publicKeyPem": public_key,
        },
    }


def signatureHeader(name: str, target: str,
                    body: bytes) -> tuple[str, str, str]:
    """Build the Cavage signature and digest headers for an inbox POST."""
    parsed = urlparse(target)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host = parsed.netloc
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    digest = "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    signing_input = "\n".join([
        f"(request-target): post {path}",
        f"host: {host}",
        f"date: {date}",
        f"digest: {digest}",
    ])
    private_key, _ = keys[name][key_versions[name]]
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=signing_input.encode(), check=True, capture_output=True).stdout
    key_id = f"{actorUri(name)}#key-{key_versions[name] + 1}"
    header = (
        f'keyId="{key_id}",algorithm="rsa-sha256",'
        'headers="(request-target) host date digest",'
        f'signature="{base64.b64encode(signature).decode()}"')
    return date, digest, header


def deliverActivity(name: str, target: str, activity: dict[str, object]) -> int:
    """Deliver one signed activity and return the remote HTTP status."""
    body = json.dumps(activity, separators=(",", ":")).encode()
    parsed = urlparse(target)
    date, digest, signature = signatureHeader(name, target, body)
    connection_type = (http.client.HTTPSConnection if parsed.scheme == "https"
                       else http.client.HTTPConnection)
    connection = connection_type(parsed.hostname, parsed.port, timeout=15)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    connection.request("POST", path, body=body, headers={
        "Host": parsed.netloc,
        "Date": date,
        "Digest": digest,
        "Content-Type": "application/activity+json",
        "Signature": signature,
    })
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


class Handler(BaseHTTPRequestHandler):
    """Serve actor documents and receive runner-only test controls."""

    def jsonResponse(self, status: int, body: dict[str, object]) -> None:
        """Write one compact JSON response."""
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        """Serve health and actor-document endpoints."""
        for name, path in ACTORS.items():
            if self.path == path:
                self.jsonResponse(200, actorDocument(name))
                return
        if self.path == "/health":
            self.jsonResponse(200, {"status": "ok"})
            return
        self.jsonResponse(404, {"error": "not found"})

    def do_POST(self) -> None:
        """Rotate a key or request a signed delivery from the runner."""
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        name = payload.get("actor", "main")
        if name not in ACTORS:
            self.jsonResponse(400, {"error": "unknown actor"})
            return
        if self.path == "/rotate":
            key_versions[name] = min(key_versions[name] + 1,
                                     len(keys[name]) - 1)
            self.jsonResponse(200, {"key_id": actorDocument(name)[
                "publicKey"]["id"]})
            return
        if self.path == "/deliver":
            target = payload.get("target")
            activity = payload.get("activity")
            if not isinstance(target, str) or not isinstance(activity, dict):
                self.jsonResponse(400, {"error": "target and activity required"})
                return
            self.jsonResponse(200, {"status": deliverActivity(
                name, target, activity)})
            return
        self.jsonResponse(404, {"error": "not found"})

    def log_message(self, _format: str, *_args: object) -> None:
        """Keep test output focused on runner assertions."""


def main() -> None:
    """Generate deterministic-lifetime keys and start the control server."""
    directory = Path(tempfile.mkdtemp(prefix="lifecycle-peer-"))
    for name in ACTORS:
        keys[name] = [makeKeyPair(directory, name, version)
                      for version in range(2)]
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
