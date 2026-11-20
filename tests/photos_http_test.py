#!/usr/bin/env python3
"""Disposable photo composer, stream, privacy, gallery and federation checks.

Run: python tests/photos_http_test.py --binary build/unspoken
"""
import argparse
import hashlib
import json
import pathlib
import re
import sqlite3
import subprocess
import tempfile
import urllib.parse

from stickers_http_test import Instance, request, until

KIND_IRI = "https://f.mws.rocks/#postKind"


def multipart(instance, fields, files):
    boundary = "photo-test-boundary"
    parts = []
    for name, value in [("csrf", instance.csrf)] + fields:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                     f'name="{name}"\r\n\r\n{value}\r\n'.encode())
    for filename, media_type, content in files:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                     f'name="attachments"; filename="{filename}"\r\n'
                     f'Content-Type: {media_type}\r\n\r\n'.encode()
                     + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return request(instance.url + "post", b"".join(parts),
                   token=instance.token,
                   content_type="multipart/form-data; boundary=" + boundary)


def run(binary, root):
    instances = []
    try:
        sender = Instance(root / "sender", binary)
        instances.append(sender)
        receiver = Instance(root / "receiver", binary)
        instances.append(receiver)
        for instance in instances:
            config = instance.path / "config.yaml"
            config.write_text(config.read_text().replace(
                "max_upload_bytes: 10", "max_upload_bytes: 1048576")
                + "\nposts_per_page: 2\n")
            instance.restart()
        assert receiver.post("follow", [("actor_uri", sender.url + "u/alice")])[0] == 302

        def followed():
            with receiver.connection() as db:
                return db.execute("SELECT 1 FROM follows WHERE state='accepted'").fetchone()
        until(followed)
        red = pathlib.Path("tests/fixtures/photos/red.png").read_bytes()
        blue = pathlib.Path("tests/fixtures/photos/blue.png").read_bytes()
        for path in ("compose?kind=PHOTO", "u/alice?kind=unknown", "remote?kind=no"):
            assert sender.get(path)[0] == 400, path
        for path, kind in (("", "social"), ("photos", "photo"),
                           ("compose", "social"),
                           ("compose?kind=photo", "photo")):
            code, _, body = sender.get(path)
            assert code == 200, body
            assert f'type="hidden" name="post_kind" value="{kind}"'.encode() in body
            assert b'<select name="post_kind"' not in body
            if kind == "photo":
                assert b'accept="image/jpeg,image/png,image/webp,image/gif,image/avif,image/jxl" required' in body
                assert b'Post photos' in body
        assert sender.post("post", [("post_kind", "unknown"), ("content", "bad")])[0] == 400
        assert sender.post("post", [("post_kind", "photo"), ("content", "no image")])[0] == 400
        for content in (b"not image", b"<svg xmlns='http://www.w3.org/2000/svg'/>"):
            assert multipart(sender, [("post_kind", "photo")], [("x.png", "image/png", content)])[0] == 400
        assert multipart(sender, [("post_kind", "photo")],
            [("a.png", "image/png", red), ("b.png", "image/png", red)])[0] == 400
        photos = []
        socials = []
        for index in range(5):
            code, headers, body = sender.post("post", [("content", f"social {index}")])
            assert code == 302, body
            socials.append(int(headers["Location"].rsplit("/", 1)[1]))
            code, headers, body = multipart(sender, [("post_kind", "photo"),
                ("attachment_description_0", 'Blue <&"'),
                ("attachment_description_1", "")],
                [("fake.svg", "image/svg+xml", blue), ("red.png", "image/png", red)])
            assert code == 302, body
            photos.append(int(headers["Location"].rsplit("/", 1)[1]))
        post_id = photos[-1]
        uri = sender.url + "p/" + str(post_id)
        wire = json.loads(request(uri, accept="application/activity+json")[2])
        assert wire[KIND_IRI] == "photo"
        assert wire["attachment"][0]["url"].endswith(".webp")
        assert wire["attachment"][0]["mediaType"] == "image/webp"
        assert wire["attachment"][0]["name"] == 'Blue <&"'
        assert wire["attachment"][1]["name"] == ""
        photo_html = sender.get(f"p/{post_id}")[2]
        assert b'class="scroll-pips"' in photo_html
        assert b'aria-label="Photo 1 of 2"' in photo_html
        assert b'aria-label="Photo 2 of 2"' in photo_html
        assert sender.post(f"post/{post_id}/edit", [("post_kind", "social"), ("content", "change")])[0] == 400
        code, _, edited_html = sender.post(f"post/{post_id}/edit",
            [("content", "caption changed")])
        assert code == 200, edited_html
        assert b'class="scroll-pips"' in edited_html
        assert json.loads(request(uri, accept="application/activity+json")[2])[KIND_IRI] == "photo"
        for token in (None, sender.token):
            for path, expected in (("?kind=photo", socials), ("photos?kind=social", photos)):
                body = request(sender.url + path, token=token)[2].decode()
                found = [int(value) for value in re.findall(r'<article class="post [^"]*" id="p(\d+)"', body)]
                assert found == list(reversed(expected))[:2], (path, found, expected)
                match = re.search(r'class="pager"><a href="([^"]+)"', body)
                assert match, body
                older_url = match[1].replace("&amp;", "&")
                assert ("/photos?" in older_url) == path.startswith("photos")
                older = request(older_url, token=token)[2].decode()
                older_ids = [int(value) for value in re.findall(r'<article class="post [^"]*" id="p(\d+)"', older)]
                assert older_ids == list(reversed(expected))[2:4], older_ids
        profile = sender.get("u/alice?kind=photo")[2].decode()
        assert 'aria-current="page">Photos' in profile
        assert 'class="profile-photo-grid"' in profile
        assert profile.count(f'class="profile-photo-tile" href="/p/{photos[-1]}"') == 2
        assert f'class="profile-photo-tile" href="/p/{socials[-1]}"' not in profile
        assert '<article class="post ' not in profile
        assert profile.count(wire["attachment"][0]["url"]) == 2
        assert profile.count(wire["attachment"][1]["url"]) == 2
        assert "kind=photo" in profile
        def received():
            with receiver.connection() as db:
                return db.execute("SELECT id FROM posts WHERE uri=? AND post_kind=1", (uri,)).fetchone()
        remote_id = until(received)[0]
        assert f'id="p{remote_id}"'.encode() in receiver.get("photos")[2]
        remote_profile = receiver.get("remote?kind=photo&uri="
            + urllib.parse.quote(sender.url + "u/alice", safe=""))[2]
        assert f'class="profile-photo-tile" href="/p/{remote_id}"'.encode() in remote_profile
        # Private photos stay absent from anonymous pages and sharing metadata.
        code, headers, body = multipart(sender, [("post_kind", "photo"),
            ("visibility", "direct"), ("sensitive", "1")], [("red.png", "image/png", red)])
        assert code == 302, body
        private_url = headers["Location"]
        assert request(private_url)[0] == 404
        private = request(private_url, token=sender.token)[2]
        assert b'property="og:image"' not in private
        private_id = private_url.rsplit("/", 1)[1]
        owner_profile = sender.get("u/alice?kind=photo")[2]
        assert f'class="profile-photo-tile" href="/p/{private_id}"'.encode() in owner_profile
        assert b'<span>Hidden photo</span>' in owner_profile
        public_profile = request(sender.url + "u/alice?kind=photo")[2]
        assert f'class="profile-photo-tile" href="/p/{private_id}"'.encode() not in public_profile
        # Reply form defaults to Social, even under a photo root.
        code, headers, body = sender.post(f"post/{post_id}/reply", [("content", "social comment")])
        assert code == 302, body
        reply_id = int(headers["Location"].rsplit("/", 1)[1])
        with sender.connection() as db:
            assert db.execute("SELECT post_kind FROM posts WHERE id=?", (reply_id,)).fetchone() == (0,)
        assert f'id="p{reply_id}"'.encode() in sender.get(f"p/{post_id}")[2]
        # Each configured encoder is used for actual HTTP photo uploads.
        large = pathlib.Path("tests/fixtures/photos/landscape.png").read_bytes()
        config_path = sender.path / "config.yaml"
        base_config = config_path.read_text()
        for encoding, quality, suffix, media_type in (
            ("jpeg", 65, ".jpg", "image/jpeg"),
            ("webp", 40, ".webp", "image/webp"),
            ("avif", 50, ".avif", "image/avif"),
            ("jpegxl", 75, ".jxl", "image/jxl")):
            config_path.write_text(base_config
                + f"\nphotos:\n  format: {encoding}\n  quality: {quality}\n")
            sender.restart()
            code, headers, body = multipart(sender, [("post_kind", "photo")],
                [("landscape.png", "image/png", large)])
            assert code == 302, (encoding, body)
            note = json.loads(request(headers["Location"],
                accept="application/activity+json")[2])
            attachment = note["attachment"][0]
            assert attachment["url"].endswith(suffix), attachment
            assert attachment["mediaType"] == media_type
            code, media_headers, compressed = request(attachment["url"])
            assert code == 200 and compressed != large
            assert media_headers["Content-Type"].startswith(media_type)
            assert b"unspoken-secret-metadata" not in compressed
        original_hash = hashlib.sha256(large).hexdigest()
        original_path = (sender.path / "uploads" / original_hash[0]
                         / (original_hash + ".png"))
        assert not original_path.exists(), "Photo pipeline retained the original"
        # With JPEG XL configured, Social still stores the original PNG bytes.
        code, headers, body = multipart(sender, [("post_kind", "social")],
            [("landscape.png", "image/png", large)])
        assert code == 302, body
        note = json.loads(request(headers["Location"],
            accept="application/activity+json")[2])
        attachment = note["attachment"][0]
        assert attachment["mediaType"] == "image/png"
        assert attachment["url"].endswith(".png")
        assert request(attachment["url"])[2] == large
        assert original_path.read_bytes() == large
        # Exercise the actual offline CLI, then the normal startup projection.
        sender.process.terminate()
        sender.process.wait(timeout=10)
        source_path = root / "nspic.sqlite"
        images = root / "nspic_images"
        images.mkdir()
        (images / "old.png").write_bytes(red)
        with sqlite3.connect(source_path) as db:
            db.executescript("""
                CREATE TABLE albums(id INTEGER PRIMARY KEY,title TEXT);
                CREATE TABLE posts(id INTEGER PRIMARY KEY,desc TEXT,
                                   upload_time INTEGER,album INTEGER);
                CREATE TABLE images(id INTEGER PRIMARY KEY,path TEXT,
                                    width INTEGER,height INTEGER,post INTEGER);
                INSERT INTO posts VALUES(1,'<old> @alice',100,NULL);
                INSERT INTO images VALUES(1,'old.png',2,3,1);
            """)
        command = [str(binary), "import-nspic", "--config",
            str(sender.path / "config.yaml"), "--source-db", str(source_path),
            "--image-dir", str(images), "--source-key", "http-test",
            "--author", "alice"]
        with sender.connection() as db:
            before = db.execute("SELECT count(*) FROM posts").fetchone()[0]
            before_jobs = db.execute("SELECT count(*) FROM ap_jobs").fetchone()[0]
        dry = subprocess.run(command + ["--dry-run"], capture_output=True,
                             text=True, check=True)
        dry_report = [json.loads(line) for line in dry.stdout.splitlines()]
        assert dry_report[-1]["status"] == "would_import", dry.stdout
        with sender.connection() as db:
            assert db.execute("SELECT count(*) FROM posts").fetchone()[0] == before
        written = subprocess.run(command, capture_output=True, text=True,
                                 check=True)
        written_report = [json.loads(line) for line in written.stdout.splitlines()]
        imported_url = written_report[-1]["post_url"]
        assert written_report[-1]["status"] == "imported"
        with sender.connection() as db:
            assert db.execute("SELECT count(*) FROM posts").fetchone()[0] == before + 1
            assert db.execute("SELECT count(*) FROM ap_jobs").fetchone()[0] == before_jobs
        sender.restart()
        imported = json.loads(request(imported_url,
            accept="application/activity+json")[2])
        assert imported[KIND_IRI] == "photo"
        assert imported["published"] == "1970-01-01T00:01:40Z"
        assert imported["content"] == "<p>&lt;old&gt; @alice</p>"
        page = json.loads(request(sender.url + "u/alice/outbox?page=true",
                                 accept="application/activity+json")[2])
        assert any(item.get("object", {}).get("id") == imported_url
                   for item in page["orderedItems"])
        print("Photo HTTP and offline import CLI checks passed")
    finally:
        for instance in reversed(instances):
            instance.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="build/unspoken", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="unspoken_photos_http_") as directory:
        run(args.binary.resolve(), pathlib.Path(directory))
