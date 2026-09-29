"""The ONLY networked code in web assessment — and it is deliberately narrow.

Every function authorizes the target through the Range scope engine *before* it
opens a socket, and refuses (raising :class:`NotAuthorizedError`) when the scope
says no. All requests are non-destructive reads (GET/HEAD) with a small timeout
and an honest User-Agent. There is no payload injection, no credential guessing,
no brute forcing, and no automated exploitation here or anywhere downstream.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from http.client import HTTPResponse
from typing import cast
from urllib.parse import urljoin, urlparse

from cloudnova.range.scope import Scope
from cloudnova.range.webassess.checks import COMMON_SENSITIVE_PATHS
from cloudnova.range.webassess.model import HttpSnapshot

USER_AGENT = "CloudNova-Range/1.0 (authorized web assessment; +passive)"
_TIMEOUT = 10.0


class NotAuthorizedError(Exception):
    """Raised when a target is not covered by the authorized scope."""


class ProbeError(Exception):
    """Raised when an authorized target could not be reached."""


def _host_of(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        raise ProbeError(f"Could not parse a host from URL: {url!r}")
    return host


def _require_authorized(url: str, scope: Scope) -> None:
    """Gate: refuse anything the scope does not explicitly authorize."""
    host = _host_of(url)
    decision = scope.authorize(host)
    if not decision.allowed:
        raise NotAuthorizedError(f"{host}: {decision.reason}")


def _open(url: str, method: str) -> HTTPResponse:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    if urlparse(url).scheme not in ("http", "https"):
        raise ProbeError(f"Refusing non-HTTP scheme: {url!r}")
    return cast(HTTPResponse, urllib.request.urlopen(request, timeout=_TIMEOUT))


def fetch(url: str, scope: Scope) -> HttpSnapshot:
    """Authorize, then GET the URL once and capture a passive snapshot."""
    _require_authorized(url, scope)
    try:
        response = _open(url, "GET")
    except urllib.error.HTTPError as exc:
        # An error status is still a valid observation (e.g. 403/404 headers).
        response = exc  # type: ignore[assignment]
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ProbeError(f"Could not reach {url}: {exc}") from exc

    with response:
        headers = dict(response.headers.items())
        cookies = response.headers.get_all("Set-Cookie") or []
        final_url = response.geturl()
        return HttpSnapshot(
            url=url,
            status=response.status,
            headers=headers,
            cookies=list(cookies),
            final_url=final_url,
            tls=urlparse(final_url or url).scheme == "https",
        )


def find_exposed_paths(
    base_url: str, scope: Scope, paths: tuple[str, ...] = COMMON_SENSITIVE_PATHS
) -> list[str]:
    """Check a small fixed list of well-known sensitive paths (authorized only).

    Uses HEAD requests and reports only which paths return a success status. This
    is standard passive hygiene checking, not directory brute forcing.
    """
    _require_authorized(base_url, scope)
    reachable: list[str] = []
    for path in paths:
        target = urljoin(base_url.rstrip("/") + "/", path)
        try:
            with _open(target, "HEAD") as response:
                if 200 <= response.status < 300:
                    reachable.append(path)
        except urllib.error.HTTPError:
            continue  # 403/404 etc. => not exposed
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return reachable
