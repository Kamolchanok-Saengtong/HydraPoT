"""
api/auth.py — one shared secret, checked on every /api/v1 request.

DELIBERATELY THE SMALLEST THING THAT WORKS. v1 is a read-only intelligence
surface with exactly one kind of consumer: a SIEM, a script or an AI agent that
the operator wired up themselves. There are no user accounts to model, so there
is nothing for OAuth, JWT refresh, roles or permissions to describe. A header
compared against one key is the honest size of that problem, and a bigger
mechanism would only be more surface to get wrong.

OFF UNTIL A KEY EXISTS. With HYDRAPOT_API_KEY unset the API stays open -- which
is what a localhost dashboard wants, and what every deployment that predates
this file already assumes. Set the key and every v1 route requires it from that
moment on. There is no half-enabled state.

That is safe to default to because exposure is gated elsewhere: hp.py refuses
to bind 0.0.0.0 without --i-accept-public-exposure. Binding publicly is the
deliberate act; this is what you turn on when you do it.

    HYDRAPOT_API_KEY=...            in .env (gitignored) or the real environment
    curl -H 'X-API-Key: ...' ...

The key is read per request, not captured at import, so rotating it in the
environment takes effect without a restart.
"""
import os
import secrets

from fastapi import Header, HTTPException

ENV_VAR = "HYDRAPOT_API_KEY"
HEADER = "X-API-Key"


def configured_key() -> str:
    """The key this deployment expects, or "" when auth is off."""
    return (os.environ.get(ENV_VAR) or "").strip()


def require_api_key(x_api_key: str = Header(
        None, alias=HEADER,
        description=f"Shared secret. Required only when {ENV_VAR} is set on "
                    f"the server; the API is open otherwise.")):
    """FastAPI dependency. Attached to the whole v1 router, never per route --
    an endpoint added later is protected by existing, not by remembering."""
    expected = configured_key()
    if not expected:
        return                          # no key configured: auth is off
    # compare_digest, not ==, so a wrong key costs the same time whatever it
    # shares with the real one. Bytes because it rejects non-ASCII str input,
    # and a header can carry anything.
    presented = (x_api_key or "").encode("utf-8", "replace")
    if not secrets.compare_digest(presented, expected.encode("utf-8")):
        raise HTTPException(status_code=401,
                            detail=f"missing or invalid {HEADER} header",
                            headers={"WWW-Authenticate": HEADER})
