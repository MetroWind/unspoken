#!/usr/bin/env python3

import html.parser
import http.cookiejar
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


TIMEOUT_SECONDS = 120
INTERVAL_SECONDS = 1
AKKOMA_PASSWORD = "test-password"
AKKOMA_SCOPES = "read write follow"
ACTIVITY_JSON = "application/activity+json"


class CsrfParser(html.parser.HTMLParser):
    """Extract CSRF tokens from Unspoken HTML forms."""

    def __init__(self) -> None:
        """Create a parser that records the first CSRF input value."""
        super().__init__()
        self.csrf: str | None = None
        self.handle_starttag = self.handleStarttag

    def handleStarttag(self, tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        """Handle an HTML start tag while looking for CSRF input fields."""
        if tag != "input":
            return
        values = {k: v or "" for k, v in attrs}
        if values.get("name") == "csrf":
            self.csrf = values.get("value", "")


@dataclass
class HttpResult:
    """Represent an HTTP response returned by runner control helpers."""

    status: int
    url: str
    body: str
    headers: urllib.response.addinfourl


def formData(fields: dict[str, Any]) -> bytes:
    """Encode form fields for application/x-www-form-urlencoded requests."""
    return urllib.parse.urlencode(fields, doseq=True).encode("utf-8")


def jsonData(fields: dict[str, Any]) -> bytes:
    """Encode a JSON request body from a mapping of fields."""
    return json.dumps(fields).encode("utf-8")


def multipartData(fields: dict[str, Any],
                  files: list[dict[str, Any]]) -> tuple[bytes, str]:
    """Build a multipart/form-data body from simple fields and files."""
    boundary = f"----unspoken-interop-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            chunks.append(f"--{boundary}\r\n".encode("ascii"))
            chunks.append(
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                .encode("utf-8"))
            chunks.append(str(item).encode("utf-8"))
            chunks.append(b"\r\n")
    for file in files:
        name = file["name"]
        filename = file["filename"]
        content_type = file.get("content_type", "application/octet-stream")
        content = file["content"]
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        chunks.append(
            f'Content-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\n'.encode("utf-8"))
        chunks.append(f"Content-Type: {content_type}\r\n\r\n"
                      .encode("ascii"))
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def fixturePng() -> bytes:
    """Return a tiny deterministic PNG used for media interop tests."""
    return bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001"
        "08060000001f15c4890000000a49444154789c636000000200"
        "0100ffff03000006000557bfab0000000049454e44ae426082")


def getUrl(url: str,
            headers: dict[str, str] | None = None) -> tuple[int, str]:
    """Fetch a URL without cookies and return the status and response body."""
    request = urllib.request.Request(
        url, headers=headers or {"User-Agent": "interop"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def waitFor(name: str, url: str) -> dict[str, str]:
    """Wait until a service URL returns a successful readiness response."""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last_status = None
    last_body = ""
    while time.monotonic() < deadline:
        try:
            last_status, last_body = getUrl(url)
            if 200 <= last_status < 300:
                print(f"{name} ready at {url}")
                return {"name": name, "url": url, "status": "ready"}
        except OSError as error:
            last_body = str(error)
        time.sleep(INTERVAL_SECONDS)
    raise RuntimeError(
        f"{name} did not become ready at {url}; "
        f"last status={last_status}, body={last_body[:500]}"
    )


class Browser:
    """Maintain cookies while issuing HTTP requests for one test user."""

    def __init__(self) -> None:
        """Create a cookie-aware opener for form and API requests."""
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies))

    def request(self, method: str, url: str,
                data: bytes | None = None,
                headers: dict[str, str] | None = None) -> HttpResult:
        """Send an HTTP request and preserve non-2xx responses as results."""
        merged_headers = {"User-Agent": "interop"}
        if headers:
            merged_headers.update(headers)
        request = urllib.request.Request(
            url, data=data, headers=merged_headers, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                body = response.read().decode("utf-8", "replace")
                return HttpResult(
                    response.status, response.geturl(), body, response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            return HttpResult(error.code, error.geturl(), body, error)

    def get(self, url: str,
            headers: dict[str, str] | None = None) -> HttpResult:
        """Send a GET request through the browser session."""
        return self.request("GET", url, headers=headers)

    def postForm(self, url: str, fields: dict[str, Any]) -> HttpResult:
        """POST URL-encoded form data through the browser session."""
        return self.request(
            "POST", url, formData(fields),
            {"Content-Type": "application/x-www-form-urlencoded"})

    def postJson(self, url: str, fields: dict[str, Any]) -> HttpResult:
        """POST a JSON body through the browser session."""
        return self.request(
            "POST", url, jsonData(fields),
            {"Content-Type": "application/json"})

    def postMultipart(self, url: str, fields: dict[str, Any],
                      files: list[dict[str, Any]]) -> HttpResult:
        """POST multipart/form-data through the browser session."""
        body, content_type = multipartData(fields, files)
        return self.request(
            "POST", url, body, {"Content-Type": content_type})


class UnspokenControl:
    """Drive Unspoken through browser-visible routes during interop tests."""

    def __init__(self, base_url: str, oidc_url: str) -> None:
        """Create a controller for one Unspoken instance and fake OIDC peer."""
        self.base_url = base_url.rstrip("/")
        self.oidc_url = oidc_url.rstrip("/")
        self.browsers: dict[str, Browser] = {}

    def browser(self, username: str) -> Browser:
        """Return the persistent browser session for a named Unspoken user."""
        if username not in self.browsers:
            self.browsers[username] = Browser()
        return self.browsers[username]

    def login(self, username: str) -> HttpResult:
        """Log in a test user through fake OIDC and complete first-run setup."""
        browser = self.browser(username)
        selected = browser.postJson(
            f"{self.oidc_url}/select-user", {"username": username})
        requireStatus(selected, 200, "select fake OIDC user")
        result = browser.get(f"{self.base_url}/login")
        if pathOf(result.url) == "/setup-username":
            return self.setupUsername(username, result.body)
        requireStatus(result, 200, "unspoken login")
        return result

    def setupUsername(self, username: str, body: str | None = None
                       ) -> HttpResult:
        """Submit the Unspoken username setup form for a new local user."""
        browser = self.browser(username)
        setup = body
        if setup is None:
            result = browser.get(f"{self.base_url}/setup-username")
            requireStatus(result, 200, "get username setup form")
            setup = result.body
        csrf = parseCsrf(setup)
        result = browser.postForm(
            f"{self.base_url}/setup-username",
            {"csrf": csrf, "username": username,
             "display_name": username.capitalize()})
        requireStatus(result, 200, "submit username setup")
        return result

    def csrfFrom(self, username: str, path: str) -> str:
        """Fetch an Unspoken page and return its CSRF token."""
        result = self.browser(username).get(f"{self.base_url}{path}")
        requireStatus(result, 200, f"get {path}")
        return parseCsrf(result.body)

    def createPost(self, username: str, fields: dict[str, Any]) -> int:
        """Create a local Unspoken post and return its numeric post id."""
        csrf = self.csrfFrom(username, "/")
        payload = {"csrf": csrf, "content": fields["content"],
                   "visibility": fields.get("visibility", "public"),
                   "summary": fields.get("summary", "")}
        if fields.get("sensitive", False):
            payload["sensitive"] = "1"
        result = self.browser(username).postForm(
            f"{self.base_url}/post", payload)
        requireStatus(result, 200, "create unspoken post")
        return postIdFromUrl(result.url)

    def createPostWithAttachment(self, username: str, fields: dict[str, Any],
                                 filename: str, content: bytes,
                                 content_type: str) -> int:
        """Create an Unspoken post with one uploaded attachment."""
        csrf = self.csrfFrom(username, "/")
        payload = {"csrf": csrf, "content": fields.get("content", ""),
                   "visibility": fields.get("visibility", "public"),
                   "summary": fields.get("summary", "")}
        if fields.get("sensitive", False):
            payload["sensitive"] = "1"
        result = self.browser(username).postMultipart(
            f"{self.base_url}/post", payload, [{
                "name": "attachments",
                "filename": filename,
                "content": content,
                "content_type": content_type,
            }])
        requireStatus(result, 200, "create unspoken attachment post")
        return postIdFromUrl(result.url)

    def updateProfile(self, username: str, fields: dict[str, Any],
                      files: list[dict[str, Any]] | None = None
                      ) -> HttpResult:
        """Submit the Unspoken rich profile edit form."""
        csrf = self.csrfFrom(username, "/profile")
        payload = {
            "csrf": csrf,
            "display_name": fields.get("display_name", ""),
            "bio": fields.get("bio", ""),
        }
        for index, field in enumerate(fields.get("profile_fields", [])):
            payload[f"field_label_{index}"] = field.get("label", "")
            payload[f"field_value_{index}"] = field.get("value", "")
        result = self.browser(username).postMultipart(
            f"{self.base_url}/profile", payload, files or [])
        requireStatus(result, 200, "update unspoken profile")
        return result

    def reply(self, username: str, post_id: int,
              fields: dict[str, Any]) -> int:
        """Create a local Unspoken reply and return its numeric post id."""
        csrf = self.csrfFrom(username, f"/p/{post_id}")
        result = self.browser(username).postForm(
            f"{self.base_url}/post/{post_id}/reply",
            {"csrf": csrf, "content": fields["content"],
             "visibility": fields.get("visibility", "public")})
        requireStatus(result, 200, "create unspoken reply")
        return postIdFromUrl(result.url)

    def follow(self, username: str, actor_uri: str,
               undo: bool = False) -> HttpResult:
        """Submit an Unspoken follow or unfollow action for a remote actor."""
        csrf = self.csrfFrom(username, "/search")
        fields = {"csrf": csrf, "actor_uri": actor_uri}
        if undo:
            fields["undo"] = "1"
        result = self.browser(username).postForm(
            f"{self.base_url}/follow", fields)
        requireStatus(result, 200, "submit unspoken follow form")
        return result

    def like(self, username: str, post_id: int,
             undo: bool = False) -> HttpResult:
        """Submit a like or unlike action from an Unspoken user."""
        return self.postAction(username, post_id, "like", undo=undo)

    def boost(self, username: str, post_id: int,
              undo: bool = False) -> HttpResult:
        """Submit a boost or unboost action from an Unspoken user."""
        return self.postAction(username, post_id, "boost", undo=undo)

    def react(self, username: str, post_id: int, emoji: str,
              undo: bool = False) -> HttpResult:
        """Submit or undo an emoji reaction from an Unspoken user."""
        return self.postAction(
            username, post_id, "react", {"emoji": emoji}, undo)

    def delete(self, username: str, post_id: int) -> HttpResult:
        """Delete an Unspoken post through the post action route."""
        return self.postAction(username, post_id, "delete")

    def postAction(self, username: str, post_id: int, action: str,
                    extra: dict[str, Any] | None = None,
                    undo: bool = False) -> HttpResult:
        """Submit a CSRF-protected action against an Unspoken post."""
        csrf = self.csrfFrom(username, f"/p/{post_id}")
        fields = {"csrf": csrf}
        if extra:
            fields.update(extra)
        if undo:
            fields["undo"] = "1"
        result = self.browser(username).postForm(
            f"{self.base_url}/post/{post_id}/{action}", fields)
        requireStatus(result, 200, f"submit unspoken {action} form")
        return result

    def search(self, username: str, query: str) -> HttpResult:
        """Run an Unspoken search as a logged-in user."""
        encoded = urllib.parse.urlencode({"q": query})
        result = self.browser(username).get(f"{self.base_url}/search?{encoded}")
        requireStatus(result, 200, "search unspoken")
        return result

    def activityJson(self, path: str) -> dict[str, Any]:
        """Fetch an Unspoken route as ActivityPub JSON."""
        result = Browser().get(
            f"{self.base_url}{path}", {"Accept": ACTIVITY_JSON})
        requireStatus(result, 200, f"fetch ActivityPub JSON {path}")
        return json.loads(result.body)


class AkkomaControl:
    """Drive Akkoma through its Mastodon-compatible HTTP API."""

    def __init__(self, base_url: str) -> None:
        """Create a controller for one Akkoma instance."""
        self.base_url = base_url.rstrip("/")
        self.client_id: str | None = None
        self.client_secret: str | None = None
        self.app_token: str | None = None
        self.tokens: dict[str, str] = {}
        self.account_ids: dict[str, str] = {}

    def ensureApp(self) -> None:
        """Create and cache OAuth application credentials if needed."""
        if self.client_id is not None and self.client_secret is not None:
            return
        data = formData({
            "client_name": "unspoken-interop",
            "redirect_uris": "urn:ietf:wg:oauth:2.0:oob",
            "scopes": AKKOMA_SCOPES,
        })
        body = self.httpJson("POST", "/api/v1/apps", data=data)
        self.client_id = body["client_id"]
        self.client_secret = body["client_secret"]

    def ensureAppToken(self) -> str:
        """Return an application token for provisioning Akkoma users."""
        self.ensureApp()
        if self.app_token is not None:
            return self.app_token
        data = formData({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": AKKOMA_SCOPES,
        })
        body = self.httpJson("POST", "/oauth/token", data=data)
        self.app_token = body["access_token"]
        return self.app_token

    def createUser(self, username: str,
                    password: str = AKKOMA_PASSWORD) -> None:
        """Create an Akkoma test user, treating existing users as ready."""
        app_token = self.ensureAppToken()
        data = formData({
            "username": username,
            "email": f"{username}@akkoma.test",
            "password": password,
            "agreement": "true",
            "locale": "en",
            "reason": "interop",
        })
        result = self.http(
            "POST", "/api/v1/accounts", data=data, token=app_token)
        if result.status in (200, 202):
            return
        if result.status == 422 and "taken" in result.body.lower():
            return
        if result.status == 400 and "taken" in result.body.lower():
            return
        raise RuntimeError(
            f"create Akkoma user failed: {result.status} {result.body[:500]}")

    def login(self, username: str,
              password: str = AKKOMA_PASSWORD) -> str:
        """Return and cache a user access token for Akkoma API calls."""
        self.ensureApp()
        if username in self.tokens:
            return self.tokens[username]
        data = formData({
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": AKKOMA_SCOPES,
        })
        body = self.httpJson("POST", "/oauth/token", data=data)
        token = body["access_token"]
        self.tokens[username] = token
        account = self.httpJson(
            "GET", "/api/v1/accounts/verify_credentials", token=token)
        self.account_ids[username] = account["id"]
        return token

    def createStatus(self, token: str, text: str,
                      in_reply_to_id: str | None = None,
                      visibility: str = "public",
                      spoiler_text: str = "",
                      sensitive: bool = False,
                      media_ids: list[str] | None = None
                      ) -> dict[str, Any]:
        """Create a public Akkoma status, optionally as a reply."""
        fields: dict[str, Any] = {"status": text, "visibility": visibility}
        if in_reply_to_id is not None:
            fields["in_reply_to_id"] = in_reply_to_id
        if spoiler_text:
            fields["spoiler_text"] = spoiler_text
        if sensitive:
            fields["sensitive"] = "true"
        if media_ids:
            fields["media_ids[]"] = media_ids
        return self.httpJson(
            "POST", "/api/v1/statuses", data=formData(fields), token=token)

    def updateStatus(self, token: str, status_id: str,
                     text: str, spoiler_text: str = "",
                     sensitive: bool = False) -> dict[str, Any]:
        """Edit an Akkoma status through the Mastodon-compatible API."""
        fields: dict[str, Any] = {"status": text}
        if spoiler_text:
            fields["spoiler_text"] = spoiler_text
        if sensitive:
            fields["sensitive"] = "true"
        return self.httpJson(
            "PUT", f"/api/v1/statuses/{status_id}",
            data=formData(fields), token=token)

    def uploadMedia(self, token: str, filename: str, content: bytes,
                    content_type: str) -> dict[str, Any]:
        """Upload one media attachment to Akkoma and return its metadata."""
        body, multipart_type = multipartData({}, [{
            "name": "file",
            "filename": filename,
            "content": content,
            "content_type": content_type,
        }])
        return self.httpJson(
            "POST", "/api/v2/media", data=body, token=token,
            content_type=multipart_type)

    def updateProfile(self, token: str, fields: dict[str, Any],
                      files: list[dict[str, Any]] | None = None
                      ) -> dict[str, Any]:
        """Update an Akkoma profile through the Mastodon-compatible API."""
        payload = {
            "display_name": fields.get("display_name", ""),
            "note": fields.get("note", ""),
        }
        for index, field in enumerate(fields.get("profile_fields", [])):
            payload[f"fields_attributes[{index}][name]"] = (
                field.get("label", ""))
            payload[f"fields_attributes[{index}][value]"] = (
                field.get("value", ""))
        body, multipart_type = multipartData(payload, files or [])
        return self.httpJson(
            "PATCH", "/api/v1/accounts/update_credentials", data=body,
            token=token, content_type=multipart_type)

    def follow(self, token: str, actor_uri: str) -> dict[str, Any]:
        """Resolve and follow an ActivityPub actor from an Akkoma account."""
        account = self.searchAccount(token, actor_uri)
        return self.httpJson(
            "POST", f"/api/v1/accounts/{account['id']}/follow",
            data=b"", token=token)

    def searchAccount(self, token: str, query: str) -> dict[str, Any]:
        """Resolve an Akkoma-visible account by URI or search query."""
        encoded = urllib.parse.urlencode(
            {"q": query, "resolve": "true", "type": "accounts"})
        body = self.httpJson(
            "GET", f"/api/v2/search?{encoded}", token=token)
        accounts = body.get("accounts", [])
        if not accounts:
            raise RuntimeError(f"Akkoma could not resolve account {query}")
        return accounts[0]

    def searchStatus(self, token: str, query: str) -> dict[str, Any] | None:
        """Resolve an Akkoma-visible status by URI or search query."""
        encoded = urllib.parse.urlencode(
            {"q": query, "resolve": "true", "type": "statuses"})
        body = self.httpJson(
            "GET", f"/api/v2/search?{encoded}", token=token)
        statuses = body.get("statuses", [])
        if not statuses:
            return None
        return statuses[0]

    def status(self, token: str, status_id: str) -> dict[str, Any] | None:
        """Fetch one Akkoma status, returning None when it is missing."""
        result = self.http(
            "GET", f"/api/v1/statuses/{status_id}", token=token)
        if result.status == 404:
            return None
        if not 200 <= result.status < 300:
            raise RuntimeError(
                f"GET status {status_id} failed: {result.status} "
                f"{result.body[:500]}")
        return json.loads(result.body)

    def like(self, token: str, status_id: str,
             undo: bool = False) -> dict[str, Any]:
        """Favourite or unfavourite an Akkoma status."""
        action = "unfavourite" if undo else "favourite"
        return self.httpJson(
            "POST", f"/api/v1/statuses/{status_id}/{action}",
            data=b"", token=token)

    def boost(self, token: str, status_id: str,
              undo: bool = False) -> dict[str, Any]:
        """Reblog or unreblog an Akkoma status."""
        action = "unreblog" if undo else "reblog"
        return self.httpJson(
            "POST", f"/api/v1/statuses/{status_id}/{action}",
            data=b"", token=token)

    def react(self, token: str, status_id: str, emoji: str,
              undo: bool = False) -> dict[str, Any]:
        """Add or remove an Akkoma emoji reaction on a status."""
        quoted = urllib.parse.quote(emoji, safe="")
        method = "DELETE" if undo else "PUT"
        return self.httpJson(
            method, f"/api/v1/pleroma/statuses/{status_id}/reactions/{quoted}",
            data=b"", token=token)

    def deleteStatus(self, token: str, status_id: str) -> dict[str, Any]:
        """Delete an Akkoma status through the API."""
        return self.httpJson(
            "DELETE", f"/api/v1/statuses/{status_id}", token=token)

    def customEmoji(self) -> list[dict[str, Any]]:
        """Return Akkoma custom emoji metadata visible to anonymous clients."""
        return self.httpJson("GET", "/api/v1/custom_emojis")

    def httpJson(self, method: str, path: str,
                  data: bytes | None = None,
                  token: str | None = None,
                  content_type: str = "application/x-www-form-urlencoded"
                  ) -> Any:
        """Send an Akkoma API request and decode a successful JSON body."""
        result = self.http(method, path, data=data, token=token,
                           content_type=content_type)
        if not 200 <= result.status < 300:
            raise RuntimeError(
                f"{method} {path} failed: {result.status} "
                f"{result.body[:500]}")
        return json.loads(result.body)

    def http(self, method: str, path: str,
             data: bytes | None = None,
             token: str | None = None,
             content_type: str = "application/x-www-form-urlencoded"
             ) -> HttpResult:
        """Send a raw Akkoma API request and return the full HTTP result."""
        headers = {"User-Agent": "interop"}
        if data is not None:
            headers["Content-Type"] = content_type
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data,
            headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read().decode("utf-8", "replace")
                return HttpResult(
                    response.status, response.geturl(), body, response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            return HttpResult(error.code, error.geturl(), body, error)


class UnspokenDatabase:
    """Read Unspoken state directly from SQLite for eventual assertions."""

    def __init__(self, path: str) -> None:
        """Create a read-only database helper for the given SQLite path."""
        self.path = path

    def connect(self) -> sqlite3.Connection:
        """Open a read-only SQLite connection with row dictionaries enabled."""
        uri = f"file:{self.path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def rows(self, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        """Run a read-only query and return rows as dictionaries."""
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query, params)]

    def scalar(self, query: str, params: tuple[Any, ...]) -> Any:
        """Run a read-only scalar query and return the first column."""
        with self.connect() as conn:
            row = conn.execute(query, params).fetchone()
            return None if row is None else row[0]

    def postByUri(self, uri: str) -> dict[str, Any] | None:
        """Return the stored Unspoken post for an ActivityPub object URI."""
        rows = self.rows("SELECT * FROM posts WHERE uri = ?", (uri,))
        return rows[0] if rows else None

    def postById(self, post_id: int) -> dict[str, Any] | None:
        """Return the stored Unspoken post with the given numeric ID."""
        rows = self.rows("SELECT * FROM posts WHERE id = ?", (post_id,))
        return rows[0] if rows else None

    def remoteActorByUri(self, uri: str) -> dict[str, Any] | None:
        """Return the cached remote actor for an ActivityPub actor URI."""
        rows = self.rows("SELECT * FROM remote_actors WHERE uri = ?", (uri,))
        return rows[0] if rows else None

    def reactionsForPost(self, uri: str) -> list[dict[str, Any]]:
        """Return emoji reactions stored for an ActivityPub post URI."""
        return self.rows(
            "SELECT * FROM reactions WHERE post_uri = ? "
            "ORDER BY created_at ASC",
            (uri,))

    def likesForPost(self, uri: str) -> list[dict[str, Any]]:
        """Return likes stored for an ActivityPub post URI."""
        return self.rows(
            "SELECT * FROM likes WHERE post_uri = ? ORDER BY created_at ASC",
            (uri,))

    def boostsForPost(self, uri: str) -> list[dict[str, Any]]:
        """Return boosts stored for an ActivityPub post URI."""
        return self.rows(
            "SELECT * FROM boosts WHERE post_uri = ? ORDER BY created_at ASC",
            (uri,))

    def attachmentsForPost(self, post_id: int) -> list[dict[str, Any]]:
        """Return attachment rows associated with a stored post."""
        return self.rows(
            "SELECT a.*, pa.sensitive AS sensitive, "
            "pa.sort_order AS sort_order "
            "FROM post_attachments pa "
            "JOIN attachments a ON a.id = pa.attachment_id "
            "WHERE pa.post_id = ? "
            "ORDER BY pa.sort_order ASC, a.id ASC",
            (post_id,))

    def countSeenActivity(self, activity_uri: str) -> int:
        """Return how many dedupe rows exist for one activity URI."""
        value = self.scalar(
            "SELECT COUNT(*) FROM seen_activities WHERE activity_uri = ?",
            (activity_uri,))
        return int(value or 0)

    def follow(self, follower_uri: str,
               followee_uri: str) -> dict[str, Any] | None:
        """Return the stored follow row for a follower/followee pair."""
        rows = self.rows(
            "SELECT * FROM follows WHERE follower_uri = ? "
            "AND followee_uri = ?",
            (follower_uri, followee_uri))
        return rows[0] if rows else None

    def jobs(self, kind: str, state: str) -> list[dict[str, Any]]:
        """Return queued jobs matching a kind and state."""
        return self.rows(
            "SELECT * FROM jobs WHERE kind = ? AND state = ? "
            "ORDER BY created_at ASC",
            (kind, state))

    def jobsByState(self, state: str) -> list[dict[str, Any]]:
        """Return all queued jobs in a given state."""
        return self.rows(
            "SELECT * FROM jobs WHERE state = ? ORDER BY created_at ASC",
            (state,))

    def jobsContaining(self, kind: str, text: str) -> list[dict[str, Any]]:
        """Return jobs of a kind whose JSON payload contains given text."""
        return self.rows(
            "SELECT * FROM jobs WHERE kind = ? AND payload_json LIKE ? "
            "ORDER BY created_at ASC",
            (kind, f"%{text}%"))

    def jobsSince(self, kind: str, min_created_at: int) -> list[dict[str, Any]]:
        """Return jobs of a kind created no earlier than a timestamp."""
        return self.rows(
            "SELECT * FROM jobs WHERE kind = ? AND created_at >= ? "
            "ORDER BY id ASC",
            (kind, min_created_at))

    def jobById(self, job_id: int) -> dict[str, Any] | None:
        """Return one queued job by ID."""
        rows = self.rows("SELECT * FROM jobs WHERE id = ?", (job_id,))
        return rows[0] if rows else None


def waitUntil(name: str, probe: Callable[[], Any]) -> Any:
    """Poll a probe until it returns a truthy value or times out."""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last_error: Exception | None = None
    last_value: Any = None
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
            last_value = value
        except Exception as error:
            last_error = error
        time.sleep(INTERVAL_SECONDS)
    if last_error is not None:
        raise RuntimeError(f"Timed out waiting for {name}: {last_error}")
    raise RuntimeError(f"Timed out waiting for {name}: last={last_value!r}")


def requireStatus(result: HttpResult, expected: int, action: str) -> None:
    """Raise a diagnostic error when an HTTP result has the wrong status."""
    if result.status != expected:
        raise RuntimeError(
            f"{action} failed: {result.status} {result.url} "
            f"{result.body[:500]}")


def parseCsrf(body: str) -> str:
    """Parse a CSRF token from an HTML response body."""
    parser = CsrfParser()
    parser.feed(body)
    if not parser.csrf:
        raise RuntimeError("No CSRF token found")
    return parser.csrf


def pathOf(url: str) -> str:
    """Return only the path component of a URL."""
    return urllib.parse.urlparse(url).path


def postIdFromUrl(url: str) -> int:
    """Extract an Unspoken numeric post id from a post URL."""
    match = re.search(r"/p/([0-9]+)(?:$|[?#])", url)
    if not match:
        raise RuntimeError(f"Could not find post id in {url}")
    return int(match.group(1))


def runPhase3(unspoken_url: str, akkoma_url: str,
                fake_oidc_url: str, db_path: str) -> dict[str, Any]:
    """Exercise phase 3 control helpers against live interop services."""
    stamp = str(int(time.time()))
    alice = "alice"
    bob = "bob"
    unspoken = UnspokenControl(unspoken_url, fake_oidc_url)
    akkoma = AkkomaControl(akkoma_url)
    db = UnspokenDatabase(db_path)

    akkoma.createUser(bob)
    bob_token = akkoma.login(bob)
    unspoken.login(alice)

    emojis = akkoma.customEmoji()
    emoji_names = {item.get("shortcode") for item in emojis}
    if "interop_blob" not in emoji_names:
        raise RuntimeError("Akkoma custom emoji :interop_blob: not available")

    post_id = unspoken.createPost(
        alice, {"content": f"phase 3 post {stamp}"})
    reply_id = unspoken.reply(
        alice, post_id, {"content": f"phase 3 reply {stamp}"})
    unspoken.like(alice, post_id)
    unspoken.like(alice, post_id, undo=True)
    unspoken.boost(alice, post_id)
    unspoken.boost(alice, post_id, undo=True)
    unspoken.react(alice, post_id, "👍")
    unspoken.react(alice, post_id, "👍", undo=True)
    unspoken.search(alice, f"phase 3 post {stamp}")

    actor_uri = f"{unspoken_url.rstrip('/')}/u/{alice}"
    akkoma.follow(bob_token, actor_uri)
    unspoken.follow(alice, f"{akkoma_url.rstrip('/')}/users/{bob}")

    status = akkoma.createStatus(bob_token, f"phase 3 status {stamp}")
    status_id = status["id"]
    akkoma.like(bob_token, status_id)
    akkoma.like(bob_token, status_id, undo=True)
    akkoma.boost(bob_token, status_id)
    akkoma.boost(bob_token, status_id, undo=True)
    akkoma.react(bob_token, status_id, ":interop_blob:")
    akkoma.react(bob_token, status_id, ":interop_blob:", undo=True)
    akkoma.deleteStatus(bob_token, status_id)

    post_uri = f"{unspoken_url.rstrip('/')}/p/{post_id}"
    stored = db.postByUri(post_uri)
    if stored is None:
        raise RuntimeError(f"Unspoken post {post_uri} was not stored")
    if db.follow(actor_uri, f"{akkoma_url.rstrip('/')}/users/{bob}") is None:
        raise RuntimeError("Unspoken follow row was not stored")

    unspoken.delete(alice, reply_id)

    return {
        "name": "phase_3_control_helpers",
        "status": "passed",
        "checks": [
            {"name": "akkoma_user", "username": bob, "status": "ready"},
            {"name": "akkoma_token", "username": bob, "status": "ready"},
            {"name": "unspoken_login", "username": alice,
             "status": "ready"},
            {"name": "unspoken_forms", "post_id": post_id,
             "reply_id": reply_id, "status": "ready"},
            {"name": "akkoma_api_actions", "status_id": status_id,
             "status": "ready"},
            {"name": "custom_emoji", "shortcode": "interop_blob",
             "status": "ready"},
            {"name": "sqlite_read_helpers", "post_uri": post_uri,
             "status": "ready"},
        ],
    }


class Phase4Context:
    """Share phase 4 service clients, users, and state lookup helpers."""

    def __init__(self, unspoken_url: str, akkoma_url: str,
                 fake_oidc_url: str, db_path: str) -> None:
        """Create reusable phase 4 test context for one runner invocation."""
        self.unspoken_url = unspoken_url.rstrip("/")
        self.akkoma_url = akkoma_url.rstrip("/")
        self.stamp = str(int(time.time()))
        self.alice = "alice"
        self.bob = "bob"
        self.unspoken = UnspokenControl(unspoken_url, fake_oidc_url)
        self.akkoma = AkkomaControl(akkoma_url)
        self.db = UnspokenDatabase(db_path)
        self.bob_token = ""

    @property
    def aliceActor(self) -> str:
        """Return Alice's Unspoken ActivityPub actor URI."""
        return f"{self.unspoken_url}/u/{self.alice}"

    @property
    def bobActor(self) -> str:
        """Return Bob's Akkoma ActivityPub actor URI."""
        return f"{self.akkoma_url}/users/{self.bob}"

    def setup(self) -> None:
        """Provision the phase 4 users and log in both peers."""
        self.akkoma.createUser(self.bob)
        self.bob_token = self.akkoma.login(self.bob)
        self.unspoken.login(self.alice)

    def ensureFollowBothDirections(self) -> None:
        """Ensure Alice and Bob have accepted follows in both directions."""
        incoming = self.db.follow(self.bobActor, self.aliceActor)
        if incoming is None or incoming.get("state") != "accepted":
            self.akkoma.follow(self.bob_token, self.aliceActor)
        waitUntil("Akkoma follow stored in unspoken", lambda: self.db.follow(
            self.bobActor, self.aliceActor))
        outgoing = self.db.follow(self.aliceActor, self.bobActor)
        if outgoing is None:
            self.unspoken.follow(self.alice, self.bobActor)
        waitUntil("Unspoken follow accepted by Akkoma",
                   self.acceptedOutgoingFollow)

    def acceptedOutgoingFollow(self) -> dict[str, Any] | None:
        """Return Alice's outgoing follow once Akkoma has accepted it."""
        follow = self.db.follow(self.aliceActor, self.bobActor)
        if follow is not None and follow.get("state") == "accepted":
            return follow
        return None

    def createAlicePostSeenByAkkoma(self, label: str
                                         ) -> tuple[int, str, dict[str, Any]]:
        """Create an Alice post and wait until Akkoma can resolve it."""
        content = f"phase 4 {label} alice {self.stamp}"
        post_id = self.unspoken.createPost(
            self.alice, {"content": content})
        post_uri = f"{self.unspoken_url}/p/{post_id}"
        status = waitUntil(
            f"Akkoma receives {post_uri}",
            lambda: self.akkoma.searchStatus(self.bob_token, post_uri))
        return post_id, post_uri, status

    def createBobPostSeenByUnspoken(self, label: str
                                         ) -> tuple[dict[str, Any],
                                                    dict[str, Any]]:
        """Create a Bob status and wait until Unspoken stores it."""
        status = self.akkoma.createStatus(
            self.bob_token, f"phase 4 {label} bob {self.stamp}")
        post = waitUntil(
            f"Unspoken receives {status['uri']}",
            lambda: self.db.postByUri(status["uri"]))
        return status, post


def testActorAndWebfinger(ctx: Phase4Context) -> dict[str, Any]:
    """Verify actor JSON, WebFinger discovery, and remote actor caching."""
    actor_json = ctx.unspoken.activityJson(f"/u/{ctx.alice}")
    if actor_json.get("id") != ctx.aliceActor:
        raise RuntimeError("Unspoken actor JSON id does not match actor URL")
    if "publicKey" not in actor_json:
        raise RuntimeError("Unspoken actor JSON did not include publicKey")

    webfinger_url = (
        f"{ctx.unspoken_url}/.well-known/webfinger?"
        + urllib.parse.urlencode({"resource": f"acct:alice@unspoken.test"}))
    status, body = getUrl(webfinger_url)
    if status != 200:
        raise RuntimeError(f"WebFinger failed: {status} {body[:500]}")
    webfinger = json.loads(body)
    self_links = [
        item for item in webfinger.get("links", [])
        if item.get("rel") == "self"
        and item.get("type") == ACTIVITY_JSON
    ]
    if not self_links or self_links[0].get("href") != ctx.aliceActor:
        raise RuntimeError("WebFinger self link did not point at Alice actor")

    account = ctx.akkoma.searchAccount(ctx.bob_token, ctx.aliceActor)
    remote = waitUntil(
        "Unspoken caches Akkoma actor",
        lambda: ctx.db.remoteActorByUri(ctx.bobActor))
    return {
        "name": "phase_4_actor_fetch_and_webfinger",
        "status": "passed",
        "objects": {
            "alice_actor": ctx.aliceActor,
            "akkoma_account_id": account["id"],
            "bob_actor": remote["uri"],
        },
    }


def testFollowBothDirections(ctx: Phase4Context) -> dict[str, Any]:
    """Verify follow acceptance from Unspoken to Akkoma and back."""
    ctx.ensureFollowBothDirections()
    incoming = ctx.db.follow(ctx.bobActor, ctx.aliceActor)
    outgoing = ctx.db.follow(ctx.aliceActor, ctx.bobActor)
    if incoming is None or incoming.get("state") != "accepted":
        raise RuntimeError("Inbound Akkoma follow was not accepted")
    if outgoing is None or outgoing.get("state") != "accepted":
        raise RuntimeError("Outbound Unspoken follow was not accepted")
    return {
        "name": "phase_4_follow_accept_both_directions",
        "status": "passed",
        "objects": {
            "incoming_follow": incoming.get("follow_activity_uri"),
            "outgoing_follow": outgoing.get("follow_activity_uri"),
        },
    }


def testPublicPostDeliveryBothDirections(ctx: Phase4Context
                                              ) -> dict[str, Any]:
    """Verify public post delivery from each peer to the other."""
    ctx.ensureFollowBothDirections()
    alice_id, alice_uri, akkoma_status = (
        ctx.createAlicePostSeenByAkkoma("post-delivery"))
    bob_status, bob_post = ctx.createBobPostSeenByUnspoken(
        "post-delivery")
    html = ctx.unspoken.browser(ctx.alice).get(f"{ctx.unspoken_url}/")
    requireStatus(html, 200, "fetch Unspoken timeline")
    if "phase 4 post-delivery bob" not in html.body:
        raise RuntimeError("Bob post did not appear in Unspoken timeline HTML")
    return {
        "name": "phase_4_public_post_delivery_both_directions",
        "status": "passed",
        "objects": {
            "alice_post_id": alice_id,
            "alice_post_uri": alice_uri,
            "akkoma_status_id": akkoma_status["id"],
            "bob_status_id": bob_status["id"],
            "bob_post_uri": bob_post["uri"],
        },
    }


def testReplyBothDirections(ctx: Phase4Context) -> dict[str, Any]:
    """Verify replies are delivered and threaded in both directions."""
    ctx.ensureFollowBothDirections()
    alice_id, alice_uri, akkoma_status = (
        ctx.createAlicePostSeenByAkkoma("reply-root"))
    bob_reply = ctx.akkoma.createStatus(
        ctx.bob_token, f"phase 4 bob reply {ctx.stamp}",
        in_reply_to_id=akkoma_status["id"])
    stored_bob_reply = waitUntil(
        f"Unspoken receives Bob reply {bob_reply['uri']}",
        lambda: ctx.db.postByUri(bob_reply["uri"]))
    if stored_bob_reply.get("in_reply_to_uri") != alice_uri:
        raise RuntimeError("Inbound reply did not preserve in_reply_to_uri")

    bob_status, bob_post = ctx.createBobPostSeenByUnspoken(
        "reply-target")
    alice_reply_id = ctx.unspoken.reply(
        ctx.alice, int(bob_post["id"]),
        {"content": f"phase 4 alice reply {ctx.stamp}"})
    alice_reply_uri = f"{ctx.unspoken_url}/p/{alice_reply_id}"
    akkoma_reply = waitUntil(
        f"Akkoma receives Alice reply {alice_reply_uri}",
        lambda: ctx.akkoma.searchStatus(ctx.bob_token, alice_reply_uri))
    return {
        "name": "phase_4_reply_delivery_both_directions",
        "status": "passed",
        "objects": {
            "alice_root_id": alice_id,
            "alice_root_uri": alice_uri,
            "bob_reply_uri": bob_reply["uri"],
            "bob_target_uri": bob_status["uri"],
            "alice_reply_uri": alice_reply_uri,
            "akkoma_reply_id": akkoma_reply["id"],
        },
    }


def testInboundLikeBoostReactAndUndo(ctx: Phase4Context
                                           ) -> dict[str, Any]:
    """Verify inbound likes, boosts, reactions, and undo handling."""
    ctx.ensureFollowBothDirections()
    _, post_uri, status = ctx.createAlicePostSeenByAkkoma(
        "interactions")
    status_id = status["id"]

    ctx.akkoma.like(ctx.bob_token, status_id)
    waitUntil("Unspoken receives inbound Like",
               lambda: ctx.db.likesForPost(post_uri))
    ctx.akkoma.like(ctx.bob_token, status_id, undo=True)
    waitUntil("Unspoken receives inbound Undo Like",
               lambda: [] if ctx.db.likesForPost(post_uri) else True)

    ctx.akkoma.boost(ctx.bob_token, status_id)
    waitUntil("Unspoken receives inbound Announce",
               lambda: ctx.db.boostsForPost(post_uri))
    ctx.akkoma.boost(ctx.bob_token, status_id, undo=True)
    waitUntil("Unspoken receives inbound Undo Announce",
               lambda: [] if ctx.db.boostsForPost(post_uri) else True)

    ctx.akkoma.react(ctx.bob_token, status_id, ":interop_blob:")
    custom = waitUntil(
        "Unspoken receives inbound custom EmojiReact",
        lambda: next((r for r in ctx.db.reactionsForPost(post_uri)
                      if r.get("emoji") == ":interop_blob:"), None))
    if not custom.get("remote_emoji_url"):
        raise RuntimeError("Custom emoji reaction did not store image URL")
    if not custom.get("remote_emoji_media_type"):
        raise RuntimeError("Custom emoji reaction did not store media type")

    ctx.akkoma.react(ctx.bob_token, status_id, "👍")
    unicode_reaction = waitUntil(
        "Unspoken receives inbound Unicode EmojiReact",
        lambda: next((r for r in ctx.db.reactionsForPost(post_uri)
                      if r.get("emoji") == "👍"), None))
    post_html = ctx.unspoken.browser(ctx.alice).get(post_uri)
    requireStatus(post_html, 200, "fetch post HTML for reactions")
    if 'class="emoji"' not in post_html.body:
        raise RuntimeError("Custom emoji reaction did not render as image")
    return {
        "name": "phase_4_inbound_like_boost_react_and_undo",
        "status": "passed",
        "objects": {
            "post_uri": post_uri,
            "akkoma_status_id": status_id,
            "custom_reaction_activity": custom.get("activity_uri"),
            "unicode_reaction_activity": unicode_reaction.get("activity_uri"),
        },
    }


def testInboundDelete(ctx: Phase4Context) -> dict[str, Any]:
    """Verify inbound Delete removes a remote Akkoma post from Unspoken."""
    ctx.ensureFollowBothDirections()
    status, post = ctx.createBobPostSeenByUnspoken("delete")
    ctx.akkoma.deleteStatus(ctx.bob_token, status["id"])
    waitUntil("Unspoken removes deleted remote post",
               lambda: True if ctx.db.postByUri(status["uri"]) is None
               else None)
    return {
        "name": "phase_4_inbound_delete",
        "status": "passed",
        "objects": {
            "akkoma_status_id": status["id"],
            "deleted_post_uri": post["uri"],
        },
    }


def runPhase4(unspoken_url: str, akkoma_url: str,
                fake_oidc_url: str, db_path: str) -> list[dict[str, Any]]:
    """Run all phase 4 Akkoma interoperability checks."""
    ctx = Phase4Context(unspoken_url, akkoma_url, fake_oidc_url, db_path)
    ctx.setup()
    return [
        testActorAndWebfinger(ctx),
        testFollowBothDirections(ctx),
        testPublicPostDeliveryBothDirections(ctx),
        testReplyBothDirections(ctx),
        testInboundLikeBoostReactAndUndo(ctx),
        testInboundDelete(ctx),
    ]


def testInboundUpdate(ctx: Phase4Context) -> dict[str, Any]:
    """Verify an Akkoma Update edits a post already known to Unspoken."""
    ctx.ensureFollowBothDirections()
    status, post = ctx.createBobPostSeenByUnspoken("update")
    updated_text = f"phase 5 updated bob {ctx.stamp}"
    ctx.akkoma.updateStatus(ctx.bob_token, status["id"], updated_text)
    updated_post = waitUntil(
        "Unspoken receives inbound Update",
        lambda: (
            post if (post := ctx.db.postByUri(status["uri"]))
            and updated_text in post.get("content_html", "")
            else None
        ))
    return {
        "name": "phase_5_inbound_update",
        "status": "passed",
        "objects": {
            "akkoma_status_id": status["id"],
            "post_uri": post["uri"],
        },
    }


def testAttachmentsWarningsAndSensitiveMedia(ctx: Phase4Context
                                             ) -> dict[str, Any]:
    """Verify media, content warnings, and sensitive flags interoperate."""
    ctx.ensureFollowBothDirections()
    media = ctx.akkoma.uploadMedia(
        ctx.bob_token, "interop.png", fixturePng(), "image/png")
    inbound_text = f"phase 5 inbound media {ctx.stamp}"
    inbound_summary = f"phase 5 inbound cw {ctx.stamp}"
    status = ctx.akkoma.createStatus(
        ctx.bob_token, inbound_text, spoiler_text=inbound_summary,
        sensitive=True, media_ids=[media["id"]])
    post = waitUntil(
        "Unspoken stores inbound media post",
        lambda: ctx.db.postByUri(status["uri"]))
    attachments = waitUntil(
        "Unspoken stores inbound attachment",
        lambda: ctx.db.attachmentsForPost(int(post["id"])))
    if post.get("summary") != inbound_summary or not post.get("sensitive"):
        raise RuntimeError("Inbound CW or sensitive flag was not stored")
    attachment = attachments[0]
    if not attachment.get("remote_url") or not attachment.get("is_image"):
        raise RuntimeError("Inbound remote image attachment was not stored")
    post_html = ctx.unspoken.browser(ctx.alice).get(
        f"{ctx.unspoken_url}/p/{post['id']}")
    requireStatus(post_html, 200, "fetch inbound media post HTML")
    if "sensitive image" not in post_html.body or inbound_summary not in (
            post_html.body):
        raise RuntimeError("Inbound CW/sensitive state did not render")

    outbound_summary = f"phase 5 outbound cw {ctx.stamp}"
    alice_id = ctx.unspoken.createPostWithAttachment(
        ctx.alice,
        {"content": f"phase 5 outbound media {ctx.stamp}",
         "summary": outbound_summary, "sensitive": True},
        "unspoken.png", fixturePng(), "image/png")
    alice_uri = f"{ctx.unspoken_url}/p/{alice_id}"
    akkoma_status = waitUntil(
        f"Akkoma receives outbound media post {alice_uri}",
        lambda: ctx.akkoma.searchStatus(ctx.bob_token, alice_uri))
    if not akkoma_status.get("sensitive"):
        raise RuntimeError("Outbound sensitive flag was not visible in Akkoma")
    if akkoma_status.get("spoiler_text") != outbound_summary:
        raise RuntimeError("Outbound content warning was not visible")
    if not akkoma_status.get("media_attachments"):
        raise RuntimeError("Outbound attachment was not visible in Akkoma")
    return {
        "name": "phase_5_attachments_cw_sensitive_media",
        "status": "passed",
        "objects": {
            "inbound_status_uri": status["uri"],
            "outbound_post_uri": alice_uri,
            "outbound_status_id": akkoma_status["id"],
        },
    }


def testFollowersOnlyAuthorization(ctx: Phase4Context) -> dict[str, Any]:
    """Verify followers-only delivery and unsigned fetch hiding."""
    ctx.ensureFollowBothDirections()
    post_id = ctx.unspoken.createPost(
        ctx.alice,
        {"content": f"phase 5 followers only {ctx.stamp}",
         "visibility": "followers"})
    post_uri = f"{ctx.unspoken_url}/p/{post_id}"
    akkoma_status = waitUntil(
        "Akkoma receives followers-only post",
        lambda: ctx.akkoma.searchStatus(ctx.bob_token, post_uri))
    anonymous = Browser().get(post_uri, {"Accept": ACTIVITY_JSON})
    if anonymous.status != 404:
        raise RuntimeError(
            f"Unsigned fetch of private post returned {anonymous.status}")
    return {
        "name": "phase_5_followers_only_authorization",
        "status": "passed",
        "objects": {
            "post_uri": post_uri,
            "akkoma_status_id": akkoma_status["id"],
        },
    }


def testDuplicateInteractionIdempotency(ctx: Phase4Context) -> dict[str, Any]:
    """Verify repeated inbound interaction state is idempotent."""
    ctx.ensureFollowBothDirections()
    _, post_uri, status = ctx.createAlicePostSeenByAkkoma(
        "duplicate-reaction")
    ctx.akkoma.react(ctx.bob_token, status["id"], "👍")
    ctx.akkoma.react(ctx.bob_token, status["id"], "👍")
    reactions = waitUntil(
        "Unspoken receives duplicate reaction attempts",
        lambda: [r for r in ctx.db.reactionsForPost(post_uri)
                 if r.get("emoji") == "👍"])
    if len(reactions) != 1:
        raise RuntimeError(
            f"Duplicate EmojiReact created {len(reactions)} rows")
    activity_uri = reactions[0].get("activity_uri")
    if activity_uri and ctx.db.countSeenActivity(activity_uri) > 1:
        raise RuntimeError("Duplicate activity dedupe table contains rows")
    return {
        "name": "phase_5_duplicate_interaction_idempotency",
        "status": "passed",
        "objects": {
            "post_uri": post_uri,
            "reaction_activity": activity_uri,
        },
    }


def testOutboundCustomEmojiReaction(ctx: Phase4Context) -> dict[str, Any]:
    """Verify Unspoken sends custom EmojiReact metadata to Akkoma."""
    ctx.ensureFollowBothDirections()
    status, post = ctx.createBobPostSeenByUnspoken(
        "outbound-custom-reaction")
    ctx.unspoken.react(ctx.alice, int(post["id"]), ":interop_blob:")

    def probe() -> dict[str, Any] | None:
        latest = ctx.akkoma.status(ctx.bob_token, status["id"])
        if latest is None:
            return None
        reactions = list(latest.get("emoji_reactions", []))
        reactions.extend(latest.get("pleroma", {}).get(
            "emoji_reactions", []))
        for reaction in reactions:
            name = reaction.get("name")
            if name in (":interop_blob:", "interop_blob",
                        "interop_blob@unspoken.test"):
                return reaction
        return None

    reaction = waitUntil("Akkoma receives outbound custom EmojiReact", probe)
    return {
        "name": "phase_5_outbound_custom_emoji_reaction",
        "status": "passed",
        "objects": {
            "akkoma_status_id": status["id"],
            "reaction": reaction,
        },
    }


def runPhase5(unspoken_url: str, akkoma_url: str,
              fake_oidc_url: str, db_path: str) -> list[dict[str, Any]]:
    """Run extended phase 5 Akkoma interoperability checks."""
    ctx = Phase4Context(unspoken_url, akkoma_url, fake_oidc_url, db_path)
    ctx.setup()
    return [
        testInboundUpdate(ctx),
        testAttachmentsWarningsAndSensitiveMedia(ctx),
        testFollowersOnlyAuthorization(ctx),
        testDuplicateInteractionIdempotency(ctx),
        testOutboundCustomEmojiReaction(ctx),
    ]


def testLocalProfileVisibleToAkkoma(ctx: Phase4Context) -> dict[str, Any]:
    """Verify Akkoma sees Unspoken actor icon, image, and fields."""
    ctx.ensureFollowBothDirections()
    display_name = f"Alice Rich {ctx.stamp}"
    bio = f"phase 6 alice bio {ctx.stamp}"
    blog = f"https://unspoken.test/profile/{ctx.stamp}"
    matrix = f"@alice-{ctx.stamp}:unspoken.test"
    ctx.unspoken.updateProfile(ctx.alice, {
        "display_name": display_name,
        "bio": bio,
        "profile_fields": [
            {"label": "Blog", "value": blog},
            {"label": "Matrix", "value": matrix},
        ],
    }, [
        {
            "name": "avatar",
            "filename": "alice-avatar.png",
            "content": fixturePng(),
            "content_type": "image/png",
        },
        {
            "name": "banner",
            "filename": "alice-banner.png",
            "content": fixturePng(),
            "content_type": "image/png",
        },
    ])

    actor_json = ctx.unspoken.activityJson(f"/u/{ctx.alice}")
    if actor_json.get("name") != display_name:
        raise RuntimeError("Unspoken actor JSON did not include display name")
    if not actor_json.get("icon", {}).get("url"):
        raise RuntimeError("Unspoken actor JSON did not include icon URL")
    if not actor_json.get("image", {}).get("url"):
        raise RuntimeError("Unspoken actor JSON did not include image URL")
    attachments = actor_json.get("attachment", [])
    labels = [item.get("name") for item in attachments
              if item.get("type") == "PropertyValue"]
    if labels != ["Blog", "Matrix"]:
        raise RuntimeError(f"Unspoken actor fields were {labels!r}")

    def akkoma_account() -> dict[str, Any] | None:
        account = ctx.akkoma.searchAccount(ctx.bob_token, ctx.aliceActor)
        if account.get("display_name") != display_name:
            return None
        fields = account.get("fields", [])
        names = [field.get("name") for field in fields]
        if "Blog" not in names or "Matrix" not in names:
            return None
        if "unspoken.test" not in account.get("avatar", ""):
            return None
        if "unspoken.test" not in account.get("header", ""):
            return None
        return account

    account = waitUntil("Akkoma refreshes Unspoken rich profile",
                        akkoma_account)
    return {
        "name": "phase_6_local_profile_visible_to_akkoma",
        "status": "passed",
        "objects": {
            "alice_actor": ctx.aliceActor,
            "akkoma_account_id": account["id"],
            "field_names": [field.get("name")
                            for field in account.get("fields", [])],
        },
    }


def testRemoteProfileVisibleToUnspoken(ctx: Phase4Context) -> dict[str, Any]:
    """Verify Unspoken renders rich profile data from an Akkoma actor."""
    ctx.ensureFollowBothDirections()
    display_name = f"Bob Rich {ctx.stamp}"
    note = f"phase 6 bob note {ctx.stamp}"
    website = f"https://akkoma.test/users/{ctx.bob}/{ctx.stamp}"
    xmpp = f"bob-{ctx.stamp}@akkoma.test"
    bob_handle = f"@{ctx.bob}@akkoma.test"
    ctx.akkoma.updateProfile(ctx.bob_token, {
        "display_name": display_name,
        "note": note,
        "profile_fields": [
            {"label": "Website", "value": website},
            {"label": "XMPP", "value": xmpp},
        ],
    }, [
        {
            "name": "avatar",
            "filename": "bob-avatar.png",
            "content": fixturePng(),
            "content_type": "image/png",
        },
        {
            "name": "header",
            "filename": "bob-header.png",
            "content": fixturePng(),
            "content_type": "image/png",
        },
    ])

    def cached_actor() -> dict[str, Any] | None:
        ctx.unspoken.search(ctx.alice, bob_handle)
        actor = ctx.db.remoteActorByUri(ctx.bobActor)
        if actor is None:
            return None
        doc = json.loads(actor.get("actor_json") or "{}")
        if doc.get("name") != display_name:
            return None
        if not doc.get("icon") or not doc.get("image"):
            return None
        field_names = [
            item.get("name") for item in doc.get("attachment", [])
            if item.get("type") == "PropertyValue"
        ]
        if "Website" not in field_names or "XMPP" not in field_names:
            return None
        return actor

    actor = waitUntil("Unspoken caches Akkoma rich profile", cached_actor)
    return {
        "name": "phase_6_remote_profile_visible_to_unspoken",
        "status": "passed",
        "objects": {
            "bob_actor": actor["uri"],
            "display_name": display_name,
            "field_names": ["Website", "XMPP"],
        },
    }


def runPhase6(unspoken_url: str, akkoma_url: str,
              fake_oidc_url: str, db_path: str) -> list[dict[str, Any]]:
    """Run rich profile interoperability checks."""
    ctx = Phase4Context(unspoken_url, akkoma_url, fake_oidc_url, db_path)
    ctx.setup()
    return [
        testLocalProfileVisibleToAkkoma(ctx),
        testRemoteProfileVisibleToUnspoken(ctx),
    ]


def runRetryPrepare(unspoken_url: str, fake_oidc_url: str,
                    db_path: str) -> dict[str, Any]:
    """Create a post while Akkoma is down and wait for a retry state."""
    stamp = str(int(time.time()))
    unspoken = UnspokenControl(unspoken_url, fake_oidc_url)
    db = UnspokenDatabase(db_path)
    unspoken.login("alice")
    min_created_at = int(time.time())
    post_id = unspoken.createPost(
        "alice", {"content": f"phase 5 retry recovery {stamp}"})
    post_uri = f"{unspoken_url.rstrip('/')}/p/{post_id}"

    def retried() -> dict[str, Any] | None:
        jobs = db.jobsSince("deliver", min_created_at)
        for job in jobs:
            if job.get("state") == "pending" and job.get("attempts", 0):
                return job
        return None

    retry_job = waitUntil("Unspoken delivery job retries", retried)
    return {
        "name": "phase_5_job_retry_prepare",
        "status": "passed",
        "objects": {
            "post_uri": post_uri,
            "post_id": post_id,
            "retried_job_id": retry_job["id"],
            "attempts": retry_job["attempts"],
        },
    }


def runRetryRecover(akkoma_url: str, db_path: str,
                    post_uri: str, retry_job_id: int) -> dict[str, Any]:
    """Verify a retried delivery succeeds after Akkoma is restarted."""
    akkoma = AkkomaControl(akkoma_url)
    db = UnspokenDatabase(db_path)
    akkoma.createUser("bob")
    bob_token = akkoma.login("bob")
    akkoma_status = waitUntil(
        "Akkoma receives retried delivery",
        lambda: akkoma.searchStatus(bob_token, post_uri))

    def recovered() -> list[dict[str, Any]] | None:
        job = db.jobById(retry_job_id)
        if job and job.get("state") == "done":
            return [job]
        return None

    jobs = waitUntil("Retried delivery jobs complete", recovered)
    return {
        "name": "phase_5_job_retry_recovery",
        "status": "passed",
        "objects": {
            "post_uri": post_uri,
            "delivered_status_id": akkoma_status["id"],
            "completed_jobs": [job["id"] for job in jobs],
        },
    }


def writeResults(path: str, status: str, tests: list[dict[str, Any]],
                  error: str | None = None) -> None:
    """Write the interop runner result artifact as JSON."""
    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "peer": {"name": "akkoma"},
        "status": status,
        "tests": tests,
    }
    if error is not None:
        result["error"] = error
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
        out.write("\n")


def main() -> int:
    """Run the interop suite configured by environment variables."""
    unspoken_url = os.environ.get("UNSPOKEN_URL", "http://unspoken.test:8080")
    akkoma_url = os.environ.get("AKKOMA_URL", "http://akkoma.test:4000")
    fake_oidc_url = os.environ.get(
        "FAKE_OIDC_URL", "http://fake-oidc.test:9000")
    results_path = os.environ.get("RESULTS_PATH", "/artifacts/results.json")
    db_path = os.environ.get("UNSPOKEN_DB", "/unspoken-data/unspoken.db")
    only = os.environ.get("INTEROP_ONLY", "")

    readiness = {
        "name": "phase_2_readiness",
        "status": "passed",
        "checks": [],
    }
    tests = [readiness]
    try:
        if only == "retry_prepare":
            readiness["checks"].append(
                waitFor("unspoken", f"{unspoken_url}/health"))
            readiness["checks"].append(waitFor(
                "fake-oidc",
                f"{fake_oidc_url}/.well-known/openid-configuration"))
            tests.append(runRetryPrepare(
                unspoken_url, fake_oidc_url, db_path))
            writeResults(results_path, "passed", tests)
            return 0
        if only == "retry_recover":
            post_uri = os.environ.get("RETRY_POST_URI", "")
            retry_job_id = int(os.environ.get("RETRY_JOB_ID", "0"))
            if not post_uri:
                raise RuntimeError("RETRY_POST_URI is required")
            if retry_job_id <= 0:
                raise RuntimeError("RETRY_JOB_ID is required")
            readiness["checks"].append(
                waitFor("akkoma", f"{akkoma_url}/api/v1/instance"))
            tests.append(runRetryRecover(
                akkoma_url, db_path, post_uri, retry_job_id))
            writeResults(results_path, "passed", tests)
            return 0
        readiness["checks"].append(
            waitFor("unspoken", f"{unspoken_url}/health"))
        readiness["checks"].append(
            waitFor("akkoma", f"{akkoma_url}/api/v1/instance"))
        readiness["checks"].append(waitFor(
            "fake-oidc",
            f"{fake_oidc_url}/.well-known/openid-configuration"))
        tests.append(runPhase3(
            unspoken_url, akkoma_url, fake_oidc_url, db_path))
        tests.extend(runPhase4(
            unspoken_url, akkoma_url, fake_oidc_url, db_path))
        tests.extend(runPhase5(
            unspoken_url, akkoma_url, fake_oidc_url, db_path))
        tests.extend(runPhase6(
            unspoken_url, akkoma_url, fake_oidc_url, db_path))
    except Exception as error:
        writeResults(results_path, "failed", tests, str(error))
        print(error, file=sys.stderr)
        return 1

    writeResults(results_path, "passed", tests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
