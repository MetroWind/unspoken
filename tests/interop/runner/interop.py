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
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


TIMEOUT_SECONDS = 120
INTERVAL_SECONDS = 1
AKKOMA_PASSWORD = "test-password"
AKKOMA_SCOPES = "read write follow"


class CsrfParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.csrf: str | None = None

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, str | None]]) -> None:
        if tag != "input":
            return
        values = {k: v or "" for k, v in attrs}
        if values.get("name") == "csrf":
            self.csrf = values.get("value", "")


@dataclass
class HttpResult:
    status: int
    url: str
    body: str
    headers: urllib.response.addinfourl


def form_data(fields: dict[str, Any]) -> bytes:
    return urllib.parse.urlencode(fields).encode("utf-8")


def json_data(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields).encode("utf-8")


def get_url(url: str,
            headers: dict[str, str] | None = None) -> tuple[int, str]:
    request = urllib.request.Request(
        url, headers=headers or {"User-Agent": "interop"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def wait_for(name: str, url: str) -> dict[str, str]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last_status = None
    last_body = ""
    while time.monotonic() < deadline:
        try:
            last_status, last_body = get_url(url)
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
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies))

    def request(self, method: str, url: str,
                data: bytes | None = None,
                headers: dict[str, str] | None = None) -> HttpResult:
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
        return self.request("GET", url, headers=headers)

    def post_form(self, url: str, fields: dict[str, Any]) -> HttpResult:
        return self.request(
            "POST", url, form_data(fields),
            {"Content-Type": "application/x-www-form-urlencoded"})

    def post_json(self, url: str, fields: dict[str, Any]) -> HttpResult:
        return self.request(
            "POST", url, json_data(fields),
            {"Content-Type": "application/json"})


class UnspokenControl:
    def __init__(self, base_url: str, oidc_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.oidc_url = oidc_url.rstrip("/")
        self.browsers: dict[str, Browser] = {}

    def browser(self, username: str) -> Browser:
        if username not in self.browsers:
            self.browsers[username] = Browser()
        return self.browsers[username]

    def login(self, username: str) -> HttpResult:
        browser = self.browser(username)
        selected = browser.post_json(
            f"{self.oidc_url}/select-user", {"username": username})
        require_status(selected, 200, "select fake OIDC user")
        result = browser.get(f"{self.base_url}/login")
        if path_of(result.url) == "/setup-username":
            return self.setup_username(username, result.body)
        require_status(result, 200, "unspoken login")
        return result

    def setup_username(self, username: str, body: str | None = None
                       ) -> HttpResult:
        browser = self.browser(username)
        setup = body
        if setup is None:
            result = browser.get(f"{self.base_url}/setup-username")
            require_status(result, 200, "get username setup form")
            setup = result.body
        csrf = parse_csrf(setup)
        result = browser.post_form(
            f"{self.base_url}/setup-username",
            {"csrf": csrf, "username": username,
             "display_name": username.capitalize()})
        require_status(result, 200, "submit username setup")
        return result

    def csrf_from(self, username: str, path: str) -> str:
        result = self.browser(username).get(f"{self.base_url}{path}")
        require_status(result, 200, f"get {path}")
        return parse_csrf(result.body)

    def create_post(self, username: str, fields: dict[str, Any]) -> int:
        csrf = self.csrf_from(username, "/")
        payload = {"csrf": csrf, "content": fields["content"],
                   "visibility": fields.get("visibility", "public"),
                   "summary": fields.get("summary", "")}
        if fields.get("sensitive", False):
            payload["sensitive"] = "1"
        result = self.browser(username).post_form(
            f"{self.base_url}/post", payload)
        require_status(result, 200, "create unspoken post")
        return post_id_from_url(result.url)

    def reply(self, username: str, post_id: int,
              fields: dict[str, Any]) -> int:
        csrf = self.csrf_from(username, f"/p/{post_id}")
        result = self.browser(username).post_form(
            f"{self.base_url}/post/{post_id}/reply",
            {"csrf": csrf, "content": fields["content"],
             "visibility": fields.get("visibility", "public")})
        require_status(result, 200, "create unspoken reply")
        return post_id_from_url(result.url)

    def follow(self, username: str, actor_uri: str,
               undo: bool = False) -> HttpResult:
        csrf = self.csrf_from(username, "/search")
        fields = {"csrf": csrf, "actor_uri": actor_uri}
        if undo:
            fields["undo"] = "1"
        result = self.browser(username).post_form(
            f"{self.base_url}/follow", fields)
        require_status(result, 200, "submit unspoken follow form")
        return result

    def like(self, username: str, post_id: int,
             undo: bool = False) -> HttpResult:
        return self.post_action(username, post_id, "like", undo=undo)

    def boost(self, username: str, post_id: int,
              undo: bool = False) -> HttpResult:
        return self.post_action(username, post_id, "boost", undo=undo)

    def react(self, username: str, post_id: int, emoji: str,
              undo: bool = False) -> HttpResult:
        return self.post_action(
            username, post_id, "react", {"emoji": emoji}, undo)

    def delete(self, username: str, post_id: int) -> HttpResult:
        return self.post_action(username, post_id, "delete")

    def post_action(self, username: str, post_id: int, action: str,
                    extra: dict[str, Any] | None = None,
                    undo: bool = False) -> HttpResult:
        csrf = self.csrf_from(username, f"/p/{post_id}")
        fields = {"csrf": csrf}
        if extra:
            fields.update(extra)
        if undo:
            fields["undo"] = "1"
        result = self.browser(username).post_form(
            f"{self.base_url}/post/{post_id}/{action}", fields)
        require_status(result, 200, f"submit unspoken {action} form")
        return result

    def search(self, username: str, query: str) -> HttpResult:
        encoded = urllib.parse.urlencode({"q": query})
        result = self.browser(username).get(f"{self.base_url}/search?{encoded}")
        require_status(result, 200, "search unspoken")
        return result


class AkkomaControl:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id: str | None = None
        self.client_secret: str | None = None
        self.app_token: str | None = None
        self.tokens: dict[str, str] = {}
        self.account_ids: dict[str, str] = {}

    def ensure_app(self) -> None:
        if self.client_id is not None and self.client_secret is not None:
            return
        data = form_data({
            "client_name": "unspoken-interop",
            "redirect_uris": "urn:ietf:wg:oauth:2.0:oob",
            "scopes": AKKOMA_SCOPES,
        })
        body = self.http_json("POST", "/api/v1/apps", data=data)
        self.client_id = body["client_id"]
        self.client_secret = body["client_secret"]

    def ensure_app_token(self) -> str:
        self.ensure_app()
        if self.app_token is not None:
            return self.app_token
        data = form_data({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": AKKOMA_SCOPES,
        })
        body = self.http_json("POST", "/oauth/token", data=data)
        self.app_token = body["access_token"]
        return self.app_token

    def create_user(self, username: str,
                    password: str = AKKOMA_PASSWORD) -> None:
        app_token = self.ensure_app_token()
        data = form_data({
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
        self.ensure_app()
        if username in self.tokens:
            return self.tokens[username]
        data = form_data({
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": AKKOMA_SCOPES,
        })
        body = self.http_json("POST", "/oauth/token", data=data)
        token = body["access_token"]
        self.tokens[username] = token
        account = self.http_json(
            "GET", "/api/v1/accounts/verify_credentials", token=token)
        self.account_ids[username] = account["id"]
        return token

    def create_status(self, token: str, text: str,
                      in_reply_to_id: str | None = None) -> dict[str, Any]:
        fields = {"status": text, "visibility": "public"}
        if in_reply_to_id is not None:
            fields["in_reply_to_id"] = in_reply_to_id
        return self.http_json(
            "POST", "/api/v1/statuses", data=form_data(fields), token=token)

    def follow(self, token: str, actor_uri: str) -> dict[str, Any]:
        account = self.search_account(token, actor_uri)
        return self.http_json(
            "POST", f"/api/v1/accounts/{account['id']}/follow",
            data=b"", token=token)

    def search_account(self, token: str, query: str) -> dict[str, Any]:
        encoded = urllib.parse.urlencode(
            {"q": query, "resolve": "true", "type": "accounts"})
        body = self.http_json(
            "GET", f"/api/v2/search?{encoded}", token=token)
        accounts = body.get("accounts", [])
        if not accounts:
            raise RuntimeError(f"Akkoma could not resolve account {query}")
        return accounts[0]

    def like(self, token: str, status_id: str,
             undo: bool = False) -> dict[str, Any]:
        action = "unfavourite" if undo else "favourite"
        return self.http_json(
            "POST", f"/api/v1/statuses/{status_id}/{action}",
            data=b"", token=token)

    def boost(self, token: str, status_id: str,
              undo: bool = False) -> dict[str, Any]:
        action = "unreblog" if undo else "reblog"
        return self.http_json(
            "POST", f"/api/v1/statuses/{status_id}/{action}",
            data=b"", token=token)

    def react(self, token: str, status_id: str, emoji: str,
              undo: bool = False) -> dict[str, Any]:
        quoted = urllib.parse.quote(emoji, safe="")
        method = "DELETE" if undo else "PUT"
        return self.http_json(
            method, f"/api/v1/pleroma/statuses/{status_id}/reactions/{quoted}",
            data=b"", token=token)

    def delete_status(self, token: str, status_id: str) -> dict[str, Any]:
        return self.http_json(
            "DELETE", f"/api/v1/statuses/{status_id}", token=token)

    def custom_emoji(self) -> list[dict[str, Any]]:
        return self.http_json("GET", "/api/v1/custom_emojis")

    def http_json(self, method: str, path: str,
                  data: bytes | None = None,
                  token: str | None = None) -> Any:
        result = self.http(method, path, data=data, token=token)
        if not 200 <= result.status < 300:
            raise RuntimeError(
                f"{method} {path} failed: {result.status} "
                f"{result.body[:500]}")
        return json.loads(result.body)

    def http(self, method: str, path: str,
             data: bytes | None = None,
             token: str | None = None) -> HttpResult:
        headers = {"User-Agent": "interop"}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
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
    def __init__(self, path: str) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        uri = f"file:{self.path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def rows(self, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query, params)]

    def post_by_uri(self, uri: str) -> dict[str, Any] | None:
        rows = self.rows("SELECT * FROM posts WHERE uri = ?", (uri,))
        return rows[0] if rows else None

    def reactions_for_post(self, uri: str) -> list[dict[str, Any]]:
        return self.rows(
            "SELECT * FROM reactions WHERE post_uri = ? "
            "ORDER BY created_at ASC",
            (uri,))

    def likes_for_post(self, uri: str) -> list[dict[str, Any]]:
        return self.rows(
            "SELECT * FROM likes WHERE post_uri = ? ORDER BY created_at ASC",
            (uri,))

    def boosts_for_post(self, uri: str) -> list[dict[str, Any]]:
        return self.rows(
            "SELECT * FROM boosts WHERE post_uri = ? ORDER BY created_at ASC",
            (uri,))

    def follow(self, follower_uri: str,
               followee_uri: str) -> dict[str, Any] | None:
        rows = self.rows(
            "SELECT * FROM follows WHERE follower_uri = ? "
            "AND followee_uri = ?",
            (follower_uri, followee_uri))
        return rows[0] if rows else None

    def jobs(self, kind: str, state: str) -> list[dict[str, Any]]:
        return self.rows(
            "SELECT * FROM jobs WHERE kind = ? AND state = ? "
            "ORDER BY created_at ASC",
            (kind, state))


def require_status(result: HttpResult, expected: int, action: str) -> None:
    if result.status != expected:
        raise RuntimeError(
            f"{action} failed: {result.status} {result.url} "
            f"{result.body[:500]}")


def parse_csrf(body: str) -> str:
    parser = CsrfParser()
    parser.feed(body)
    if not parser.csrf:
        raise RuntimeError("No CSRF token found")
    return parser.csrf


def path_of(url: str) -> str:
    return urllib.parse.urlparse(url).path


def post_id_from_url(url: str) -> int:
    match = re.search(r"/p/([0-9]+)(?:$|[?#])", url)
    if not match:
        raise RuntimeError(f"Could not find post id in {url}")
    return int(match.group(1))


def run_phase_3(unspoken_url: str, akkoma_url: str,
                fake_oidc_url: str, db_path: str) -> dict[str, Any]:
    stamp = str(int(time.time()))
    alice = "alice"
    bob = "bob"
    unspoken = UnspokenControl(unspoken_url, fake_oidc_url)
    akkoma = AkkomaControl(akkoma_url)
    db = UnspokenDatabase(db_path)

    akkoma.create_user(bob)
    bob_token = akkoma.login(bob)
    unspoken.login(alice)

    emojis = akkoma.custom_emoji()
    emoji_names = {item.get("shortcode") for item in emojis}
    if "interop_blob" not in emoji_names:
        raise RuntimeError("Akkoma custom emoji :interop_blob: not available")

    post_id = unspoken.create_post(
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

    status = akkoma.create_status(bob_token, f"phase 3 status {stamp}")
    status_id = status["id"]
    akkoma.like(bob_token, status_id)
    akkoma.like(bob_token, status_id, undo=True)
    akkoma.boost(bob_token, status_id)
    akkoma.boost(bob_token, status_id, undo=True)
    akkoma.react(bob_token, status_id, ":interop_blob:")
    akkoma.react(bob_token, status_id, ":interop_blob:", undo=True)
    akkoma.delete_status(bob_token, status_id)

    post_uri = f"{unspoken_url.rstrip('/')}/p/{post_id}"
    stored = db.post_by_uri(post_uri)
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


def write_results(path: str, status: str, tests: list[dict[str, Any]],
                  error: str | None = None) -> None:
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
    unspoken_url = os.environ.get("UNSPOKEN_URL", "http://unspoken.test:8080")
    akkoma_url = os.environ.get("AKKOMA_URL", "http://akkoma.test:4000")
    fake_oidc_url = os.environ.get(
        "FAKE_OIDC_URL", "http://fake-oidc.test:9000")
    results_path = os.environ.get("RESULTS_PATH", "/artifacts/results.json")
    db_path = os.environ.get("UNSPOKEN_DB", "/unspoken-data/unspoken.db")

    readiness = {
        "name": "phase_2_readiness",
        "status": "passed",
        "checks": [],
    }
    tests = [readiness]
    try:
        readiness["checks"].append(
            wait_for("unspoken", f"{unspoken_url}/health"))
        readiness["checks"].append(
            wait_for("akkoma", f"{akkoma_url}/api/v1/instance"))
        readiness["checks"].append(wait_for(
            "fake-oidc",
            f"{fake_oidc_url}/.well-known/openid-configuration"))
        tests.append(run_phase_3(
            unspoken_url, akkoma_url, fake_oidc_url, db_path))
    except Exception as error:
        write_results(results_path, "failed", tests, str(error))
        print(error, file=sys.stderr)
        return 1

    write_results(results_path, "passed", tests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
