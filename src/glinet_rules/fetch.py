"""Constrained HTTPS fetching of upstream rule data.

Design rules (see SECURITY.md):

* HTTPS only, to an allowlisted host, described by config/expected-sources.json.
* Bounded: timeout, response size cap, redirect cap. Every redirect hop is
  re-checked against the same scheme/host rules.
* Pinned: a branch name is resolved to an immutable commit SHA first, and the
  content is then downloaded from a URL containing that SHA.
* Never executes upstream code and never clones an upstream repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import Policy, SourceSpec
from .errors import FetchError

#: Hosts this project is willing to talk to. Release-asset downloads redirect
#: from github.com to a githubusercontent storage URL, so both appear here;
#: nothing else does.
ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "raw.githubusercontent.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)

#: Prefixes that mean "this is an error page, not rule data".
_HTML_MARKERS = (b"<!doctype html", b"<html", b"<?xml")


@dataclass(frozen=True)
class FetchResult:
    """One downloaded upstream file plus everything needed to reproduce it."""

    key: str
    slug: str
    url: str
    revision: str
    revision_kind: str
    sha256: str
    size_bytes: int
    downloaded_at: str
    text: str

    def as_metadata(self) -> dict:
        return {
            "key": self.key,
            "name": self.slug,
            "url": self.url,
            "revision": self.revision,
            "revision_kind": self.revision_kind,
            "source_sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "downloaded_at": self.downloaded_at,
        }


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchError(f"refusing non-HTTPS URL: {url}")
    if parts.hostname not in ALLOWED_HOSTS:
        raise FetchError(f"refusing URL on non-allowlisted host {parts.hostname!r}: {url}")


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect hop instead of trusting the chain."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener(max_redirects: int) -> urllib.request.OpenerDirector:
    handler = _BoundedRedirectHandler()
    handler.max_redirections = max_redirects
    return urllib.request.build_opener(handler)


def _auth_headers() -> dict[str, str]:
    """Use GITHUB_TOKEN when present, purely to avoid API rate limiting."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def http_get(url: str, *, policy: Policy, max_bytes: int, accept: str = "*/*") -> bytes:
    """GET `url` under the configured limits, or raise FetchError."""
    _check_url(url)
    fetch = policy.section("fetch")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": fetch["user_agent"], "Accept": accept, **_auth_headers()},
    )
    opener = _build_opener(int(fetch["max_redirects"]))
    try:
        with opener.open(request, timeout=float(fetch["timeout_seconds"])) as response:
            if response.status != 200:
                raise FetchError(f"{url}: expected HTTP 200, got {response.status}")

            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > max_bytes:
                        raise FetchError(
                            f"{url}: Content-Length {declared} exceeds limit {max_bytes}"
                        )
                except ValueError:
                    pass  # A malformed header is not fatal; the read cap still applies.

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"{url}: response exceeds size limit of {max_bytes} bytes")
                chunks.append(chunk)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"{url}: HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"{url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise FetchError(f"{url}: timed out") from exc

    body = b"".join(chunks)
    if not body:
        raise FetchError(f"{url}: empty response body")
    return body


def _reject_html(url: str, body: bytes) -> None:
    head = body[:512].lstrip().lower()
    for marker in _HTML_MARKERS:
        if head.startswith(marker):
            raise FetchError(
                f"{url}: response looks like an HTML/XML page, not rule data "
                "(a cached error page must never become routing input)"
            )


def _decode(url: str, body: bytes) -> str:
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FetchError(f"{url}: response is not valid UTF-8: {exc}") from exc


def resolve_commit_sha(spec: SourceSpec, *, policy: Policy) -> str:
    """Resolve a branch/tag name to the immutable commit SHA it points at."""
    url = f"https://api.github.com/repos/{spec.owner}/{spec.repo}/commits/{spec.ref}"
    body = http_get(url, policy=policy, max_bytes=1_048_576, accept="application/vnd.github+json")
    try:
        sha = json.loads(body)["sha"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise FetchError(f"{url}: could not read commit SHA from API response") from exc
    if not isinstance(sha, str) or len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha):
        raise FetchError(f"{url}: API returned an implausible commit SHA {sha!r}")
    return sha


def _resolve_release_asset(spec: SourceSpec, *, policy: Policy) -> tuple[str, str]:
    """Return (download_url, tag) for a named asset on a GitHub release."""
    suffix = "latest" if spec.ref == "latest" else f"tags/{spec.ref}"
    url = f"https://api.github.com/repos/{spec.owner}/{spec.repo}/releases/{suffix}"
    body = http_get(url, policy=policy, max_bytes=4_194_304, accept="application/vnd.github+json")
    try:
        release = json.loads(body)
        tag = release["tag_name"]
        assets = release["assets"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise FetchError(f"{url}: could not read release metadata") from exc
    for asset in assets:
        if asset.get("name") == spec.path:
            return asset["browser_download_url"], tag
    raise FetchError(f"{url}: release {tag} has no asset named {spec.path!r}")


def fetch_source(spec: SourceSpec, *, policy: Policy) -> FetchResult:
    """Download one configured upstream source, pinned and size-limited."""
    max_bytes = int(policy.value("fetch", spec.max_bytes_key))

    if spec.kind == "github_raw":
        sha = resolve_commit_sha(spec, policy=policy)
        url = f"https://raw.githubusercontent.com/{spec.owner}/{spec.repo}/{sha}/{spec.path}"
        revision, revision_kind = sha, "commit"
    elif spec.kind == "github_release_asset":
        url, tag = _resolve_release_asset(spec, policy=policy)
        revision, revision_kind = tag, "release_tag"
    else:
        raise FetchError(f"source {spec.key!r}: unsupported kind {spec.kind!r}")

    body = http_get(url, policy=policy, max_bytes=max_bytes)
    _reject_html(url, body)

    return FetchResult(
        key=spec.key,
        slug=spec.slug,
        url=url,
        revision=revision,
        revision_kind=revision_kind,
        sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        downloaded_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        text=_decode(url, body),
    )
