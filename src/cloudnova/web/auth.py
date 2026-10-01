"""Session handling for the dashboard: cookies in, Supabase identity out.

The dashboard holds no session store of its own. The cookie carries Supabase's
own tokens, and the authoritative question "is this a real user?" is answered
by asking Supabase on each request rather than by trusting anything the cookie
says. That costs one round trip per page and buys a property worth having: a
forged or tampered cookie cannot even render the shell of a signed-in page.

Tokens are stored in ``HttpOnly`` cookies so page scripts cannot read them, and
``SameSite=Lax`` so a cross-site form POST does not carry them - which is what
stands in for CSRF tokens on the form routes here.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request, Response

from cloudnova.platform.client import AuthError, Session, SupabaseClient, SupabaseError

ACCESS_COOKIE = "cn_access"
REFRESH_COOKIE = "cn_refresh"
ORG_COOKIE = "cn_org"

# Paths reachable without a session. Everything else redirects to /login when
# the platform is configured.
PUBLIC_PATHS = frozenset({"/health", "/login", "/signup"})


@dataclass(frozen=True)
class CurrentUser:
    """A verified signed-in user, for the duration of one request."""

    user_id: str
    email: str
    access_token: str


def secure_request(request: Request) -> bool:
    """Whether to mark cookies Secure.

    Keyed on the scheme the *browser* used, not the hostname. Local
    development is plain HTTP, where a Secure cookie is silently dropped and
    login would appear to do nothing. Deployments terminate TLS at a proxy and
    reach the app over HTTP, so the forwarded scheme is what tells the truth -
    ``request.url.scheme`` alone would say "http" and leave the flag off in
    exactly the case that needs it.
    """
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return (forwarded or request.url.scheme) == "https"


def set_session(response: Response, session: Session, *, secure: bool) -> None:
    common = {"httponly": True, "samesite": "lax", "secure": secure, "path": "/"}
    response.set_cookie(ACCESS_COOKIE, session.access_token, **common)  # type: ignore[arg-type]
    if session.refresh_token:
        response.set_cookie(REFRESH_COOKIE, session.refresh_token, **common)  # type: ignore[arg-type]


def set_org(response: Response, org_id: str, *, secure: bool) -> None:
    response.set_cookie(ORG_COOKIE, org_id, httponly=True, samesite="lax", secure=secure, path="/")


def clear_session(response: Response) -> None:
    for name in (ACCESS_COOKIE, REFRESH_COOKIE, ORG_COOKIE):
        response.delete_cookie(name, path="/")


@dataclass
class Resolved:
    """Outcome of resolving a request's cookies against Supabase."""

    user: CurrentUser | None = None
    # Set when the access token was refreshed mid-request, so the caller can
    # write the new tokens back onto the response.
    refreshed: Session | None = None
    # Set when the cookie was present but no longer usable, so the caller can
    # clear it instead of leaving the browser to retry a dead token forever.
    clear: bool = False


def resolve(request: Request, client: SupabaseClient) -> Resolved:
    """Turn request cookies into a verified user, refreshing if needed."""
    access = request.cookies.get(ACCESS_COOKIE, "")
    refresh = request.cookies.get(REFRESH_COOKIE, "")
    if not access and not refresh:
        return Resolved()

    if access:
        try:
            user = client.get_user(access)
            return Resolved(user=_user_from(user, access))
        except AuthError:
            pass  # expired or revoked - fall through to the refresh attempt
        except SupabaseError:
            # Supabase unreachable. Do not clear the cookie over an outage.
            return Resolved()

    if not refresh:
        return Resolved(clear=True)

    try:
        session = client.refresh(refresh)
    except AuthError:
        return Resolved(clear=True)
    except SupabaseError:
        return Resolved()

    try:
        user = client.get_user(session.access_token)
    except SupabaseError:
        return Resolved(clear=True)
    return Resolved(user=_user_from(user, session.access_token), refreshed=session)


def _user_from(payload: dict[str, object], access_token: str) -> CurrentUser:
    return CurrentUser(
        user_id=str(payload.get("id") or ""),
        email=str(payload.get("email") or ""),
        access_token=access_token,
    )
