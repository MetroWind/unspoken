#!/usr/bin/env python3
"""Disposable local two-instance sticker integration test; no OIDC needed.

Run after building: python tests/stickers_http_test.py --binary build/unspoken
Seeds test users/sessions directly into disposable databases. All HTTP
requests, signatures, queued delivery, and remote attachment handling use
the real application. Requires loopback networking and openssl.
"""

import argparse
import html
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, fields=None, token=None, accept=None, method=None, content_type=None):
    headers = {}
    if token:
        headers["Cookie"] = "unspoken-session=" + token
    if accept:
        headers["Accept"] = accept
    if content_type:
        headers["Content-Type"] = content_type
    data = fields if isinstance(fields, bytes) else (
        None if fields is None else urllib.parse.urlencode(fields).encode())
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.code, response.headers, response.read()


def until(operation, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = operation()
            if result:
                return result
        except (OSError, sqlite3.OperationalError):
            pass
        time.sleep(.1)
    raise AssertionError("Timed out waiting for application state")


class Instance:
    def __init__(self, path, binary):
        self.path = path
        path.mkdir()
        (path / "uploads").mkdir()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/"
        self.db = path / "app.sqlite"
        self.stickers = path / "stickers"
        (self.stickers / "cats").mkdir(parents=True)
        self.filename = "A sleepy cat%?#.WEBP"
        # Opaque bytes exercise metadata-only discovery; no decoding occurs.
        self.image = b"image" * 50000
        (self.stickers / "cats" / self.filename).write_bytes(self.image)
        config = path / "config.yaml"
        config.write_text(f"""
url_root: {self.url}
listen_port: {port}
database_path: {self.db}
attachment_dir: {path / 'uploads'}
sticker_dir: {self.stickers}
max_upload_bytes: 10
job_workers: 1
job_retry_base_delay_seconds: 1
link_previews:
  enabled: false
oidc:
  issuer: https://unused.test/
  client_id: test
  client_secret: test
dev:
  allow_http_url_root: true
  outbound_allow_private_hosts: [127.0.0.1]
""")
        self.command = [str(binary), "-c", str(config)]
        self.log = (path / "server.log").open("w+")
        self.process = subprocess.Popen(self.command,
                                        stdout=self.log, stderr=self.log)
        try:
            until(lambda: self.ready())
        except Exception:
            self.stop()
            print((path / "server.log").read_text())
            raise
        key = subprocess.check_output(["openssl", "genrsa", "2048"],
                                      stderr=subprocess.DEVNULL)
        pub = subprocess.check_output(["openssl", "rsa", "-pubout"],
                                      input=key, stderr=subprocess.DEVNULL)
        self.token = "test-session"
        with self.connection() as db:
            db.execute("""INSERT INTO users (username,display_name,bio,
                oidc_iss,oidc_sub,private_key_pem,public_key_pem,created_at)
                VALUES ('alice','Alice','','iss','sub',?,?,?)""",
                       (key.decode(), pub.decode(), int(time.time())))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                       (self.token, 1, int(time.time()), int(time.time()) + 3600))
        # Startup registers local actors in the federation store.
        self.restart()

    def restart(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.process = subprocess.Popen(self.command,
                                        stdout=self.log, stderr=self.log)
        until(lambda: self.ready())
        code, _, body = self.get("compose")
        assert code == 200, body
        self.csrf = re.search(rb'name="csrf" value="([^"]+)"', body)[1].decode()

    def ready(self):
        if self.process.poll() is not None:
            raise RuntimeError("Application exited during startup")
        return request(self.url + "health")[0] == 200

    def connection(self):
        return sqlite3.connect(self.db, timeout=10)

    def get(self, path):
        return request(self.url + path, token=self.token)

    def post(self, path, fields):
        return request(self.url + path, [("csrf", self.csrf)] + list(fields),
                       token=self.token)

    def stop(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.log.close()


def run(binary, root):
    instances = []
    try:
        sender = Instance(root / "sender", binary)
        instances.append(sender)
        receiver = Instance(root / "receiver", binary)
        instances.append(receiver)
        code, _, catalog = sender.get("stickers/catalog")
        assert code == 200
        sticker = json.loads(catalog)[0]["stickers"][0]
        code, headers, body = request(sticker["url"])
        assert code == 200 and body == sender.image
        assert headers["Content-Type"] == "image/webp"
        assert headers["Cache-Control"] == "public, no-cache"
        assert headers["X-Content-Type-Options"] == "nosniff"
        code, head_headers, body = request(sticker["url"], method="HEAD")
        assert code == 200 and body == b""
        assert int(head_headers["Content-Length"]) == len(sender.image)
        assert request(sender.url + "stickers/catalog")[0] == 401
        for path in ["../cats/a.png", "cats/%2e%2e", "cats/a%2fb.png",
                     "cats/a%5cb.png", "cats/a%00.png", "cats/.hidden.png"]:
            assert request(sender.url + "stickers/" + path)[0] == 404, path
        for fields in [[("sticker_action", "oops")],
                       [("sticker_action", "set")],
                       [("sticker_action", "set"), ("sticker", "https://evil.test/a.png")],
                       [("sticker_action", "keep"), ("sticker", sticker["key"])],
                       [("sticker_action", "keep"), ("sticker_action", "clear")],
                       [("sticker", ""), ("sticker", "")]]:
            assert sender.post("post", fields)[0] == 400, fields
        boundary = "sticker-test-boundary"
        for action_fields in [[("sticker_action", "keep"), ("sticker_action", "clear")],
                              [("sticker_action", "set"), ("sticker", sticker["key"])]]:
            fields = [("csrf", sender.csrf)] + action_fields
            raw = "".join(f'--{boundary}\r\nContent-Disposition: form-data; '
                          f'name="{name}"\r\n\r\n{value}\r\n'
                          for name, value in fields) + f"--{boundary}--\r\n"
            code, _, body = request(sender.url + "post", raw.encode(), token=sender.token,
                content_type="multipart/form-data; boundary=" + boundary)
            expected = 400 if action_fields[1][0] == "sticker_action" else 302
            assert code == expected, body
        # Static retrieval is independent of the catalog and supports Unicode.
        extra = sender.stickers / "cats" / "こんにちは.png"
        extra.write_bytes(sender.image)
        extra_url = sender.url + "stickers/cats/" + urllib.parse.quote(extra.name)
        assert request(extra_url)[2] == sender.image
        (sender.stickers / "cats/link.png").symlink_to(extra)
        (sender.stickers / "linked").symlink_to(sender.stickers / "cats")
        assert request(sender.url + "stickers/cats/link.png")[0] == 404
        linked_url = sender.url + "stickers/linked/" + urllib.parse.quote(extra.name)
        assert request(linked_url)[0] == 404
        if os.geteuid() != 0:
            extra.chmod(0)
            assert request(extra_url)[0] == 500
            extra.chmod(0o600)
        extra.unlink()
        # Follow across two real servers to exercise signed Create/Update.
        code, _, body = receiver.post("follow", [("actor_uri", sender.url + "u/alice")])
        assert code == 302, body

        def accepted():
            with receiver.connection() as db:
                return db.execute("SELECT 1 FROM follows WHERE state='accepted'").fetchone()
        until(accepted)
        # A real outbound enqueue failure aborts the whole post transaction.
        reject_jobs = ("CREATE TRIGGER reject_jobs BEFORE INSERT ON ap_jobs "
                       "BEGIN SELECT RAISE(ABORT,'test enqueue failure'); END")
        with sender.connection() as db:
            baseline = db.execute("SELECT count(*) FROM posts").fetchone()[0]
            db.execute(reject_jobs)
        assert sender.post("post", [("sticker_action", "set"),
                                    ("sticker", sticker["key"])])[0] == 500
        with sender.connection() as db:
            assert db.execute("SELECT count(*) FROM posts").fetchone()[0] == baseline
            db.execute("DROP TRIGGER reject_jobs")
        code, headers, body = sender.post("post", [
            ("sticker_action", "set"), ("sticker", sticker["key"])])
        assert code == 302, body
        post_path = urllib.parse.urlsplit(headers["Location"]).path.lstrip("/")
        post_id = post_path.split("/")[-1]
        uri = sender.url + post_path
        code, _, wire = request(uri, accept="application/activity+json")
        assert code == 200
        assert json.loads(wire)["attachment"][0]["url"] == sticker["url"]
        assert json.loads(wire)["attachment"][0]["name"] == sticker["name"]

        def received():
            with receiver.connection() as db:
                return db.execute("SELECT id FROM posts WHERE uri=?", (uri,)).fetchone()
        remote_id = until(received)[0]
        with receiver.connection() as db:
            role, name, url = db.execute("""SELECT pa.role,pa.description,a.remote_url
                FROM post_attachments pa JOIN attachments a ON a.id=pa.attachment_id
                WHERE pa.post_id=?""", (remote_id,)).fetchone()
            assert role == 0 and name == sticker["name"] and url == sticker["url"]
        code, _, remote_html = receiver.get(f"p/{remote_id}")
        assert code == 200 and html.escape(sticker["url"]).encode() in remote_html
        assert request(url)[2] == sender.image
        assert sender.get("compose?reply_to=" + post_id)[0] == 200
        assert sender.get(f"post/{post_id}/edit")[0] == 200
        code, reply_headers, body = sender.post(f"post/{post_id}/reply", [
            ("sticker_action", "set"), ("sticker", sticker["key"])])
        assert code == 302, body
        # Simulate another publisher using the same URL with a different
        # ActivityPub name. Receiver must preserve both post descriptions.
        reply_id = reply_headers["Location"].split("/")[-1]
        reply_uri = sender.url + "p/" + reply_id
        with sender.connection() as db:
            db.execute("UPDATE post_attachments SET description=? WHERE post_id=?",
                       ("Different description", reply_id))
        assert sender.post(f"post/{reply_id}/edit", [
            ("content", "Reply updated"), ("sticker_action", "keep")])[0] == 200
        def independentDescriptions():
            with receiver.connection() as db:
                rows = dict(db.execute("""SELECT p.uri,pa.description FROM posts p
                    JOIN post_attachments pa ON pa.post_id=p.id
                    WHERE p.uri IN (?,?)""", (uri, reply_uri)))
                return (rows.get(uri) == sticker["name"] and
                        rows.get(reply_uri) == "Different description")
        until(independentDescriptions)
        assert sender.post(f"post/{post_id}/edit", [
            ("sticker_action", "clear")])[0] == 400
        with sender.connection() as db:
            db.execute(reject_jobs)
        assert sender.post(f"post/{post_id}/edit", [
            ("content", "must roll back"), ("sticker_action", "clear")])[0] == 500
        with sender.connection() as db:
            assert db.execute("SELECT content_source FROM posts WHERE id=?",
                              (post_id,)).fetchone()[0] == ""
            assert db.execute("SELECT role FROM post_attachments WHERE post_id=?",
                              (post_id,)).fetchone()[0] == 1
            db.execute("DROP TRIGGER reject_jobs")
        # Native editors and reply composers apply ownership/audience checks.
        with sender.connection() as db:
            db.execute("""INSERT INTO users (username,display_name,bio,oidc_iss,
                oidc_sub,private_key_pem,public_key_pem,created_at)
                SELECT 'other','','','iss','other',private_key_pem,
                public_key_pem,created_at FROM users WHERE id=1""")
            other_id = db.execute("SELECT id FROM users WHERE username='other'").fetchone()[0]
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                       ("other-session", other_id, int(time.time()), int(time.time()) + 3600))
        assert request(sender.url + f"post/{post_id}/edit", token="other-session")[0] == 404
        assert request(sender.url + "compose")[0] == 401
        code, private_headers, body = sender.post("post", [
            ("content", "private"), ("visibility", "direct")])
        assert code == 302, body
        private_id = private_headers["Location"].split("/")[-1]
        assert request(sender.url + "compose?reply_to=" + private_id,
                       token="other-session")[0] == 404
        assert sender.get("compose?reply_to=" + private_id)[0] == 200
        # Publish a new version and restart while keeping the old public URL.
        (sender.stickers / "cats/v2.webp").write_bytes(b"new artwork")
        sender.restart()
        assert request(sticker["url"])[2] == sender.image
        assert len(json.loads(sender.get("stickers/catalog")[2])[0]["stickers"]) == 2
        # Text edits keep a saved sticker without consulting the live file.
        (sender.stickers / "cats" / sender.filename).unlink()
        assert request(sticker["url"])[0] == 404
        code, _, body = sender.post(f"post/{post_id}/edit", [
            ("content", "Updated"), ("sticker_action", "keep")])
        assert code == 200, body
        def updated():
            with receiver.connection() as db:
                row = db.execute("SELECT content_html FROM posts WHERE uri=?",
                                 (uri,)).fetchone()
                return row and "Updated" in row[0]
        until(updated)
        assert json.loads(request(uri, accept="application/activity+json")[2])[
            "attachment"][0]["name"] == sticker["name"]
        assert not list((sender.path / "uploads").rglob("*"))
        print("Sticker HTTP, native forms, rollback, and two-instance Create/Update: passed")
    except Exception:
        for instance in instances:
            instance.log.flush()
            print((instance.path / "server.log").read_text()[-6000:])
        raise
    finally:
        for instance in reversed(instances):
            instance.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/unspoken")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="unspoken_sticker_http_") as directory:
        run(pathlib.Path(args.binary).resolve(), pathlib.Path(directory))
