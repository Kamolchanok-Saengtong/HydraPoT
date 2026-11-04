"""
console/login_page.py — the sign-in, sign-out and no-account pages.

PLAIN HTML, NOT DASH, on purpose. A Dash login page would need the session gate
to let `/_dash-update-component` through so the form's callbacks could fire --
and that endpoint is what serves every chart's data. The gate would have a hole
in exactly the shape of the thing it protects. Hand-written HTML has no
callbacks, so the gate stays closed around the whole Dash app.

Colors are imported from console/theme.py rather than restated, so the login
page cannot drift from the dashboard it fronts.
"""
from html import escape

from console.theme import (CARD, CRITICAL, INK, INK_3, PAPER, SIDEBAR_BG,
                           SIDEBAR_FG, Y_400, Y_500, Y_700)


def _attr(value) -> str:
    """Escape a value going into an HTML attribute.

    `next` arrives from the query string, so without this a crafted link puts
    arbitrary markup in the page -- a reflected XSS on the login form, which is
    the one page guaranteed to be visited by someone about to type a password.
    quote=True is what escapes the quote that would end the attribute.
    """
    return escape(str(value or ""), quote=True)

_CSS = f"""
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; background: {PAPER}; color: {INK};
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI',
                 Roboto, Helvetica, Arial, sans-serif;
    display: flex; align-items: center; justify-content: center; padding: 24px;
  }}
  .card {{
    width: 100%; max-width: 380px; background: {CARD}; border-radius: 14px;
    border: 1px solid rgba(23,21,18,0.08);
    box-shadow: 0 1px 2px rgba(23,21,18,0.04), 0 12px 32px rgba(23,21,18,0.07);
    padding: 32px 30px;
  }}
  .brand {{ display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }}
  .brand img {{ width: 34px; height: 34px; }}
  .brand h1 {{ font-size: 19px; margin: 0; letter-spacing: -0.01em; }}
  .sub {{ color: {INK_3}; font-size: 13px; margin: 0 0 26px; }}
  label {{
    display: block; font-size: 11px; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: {INK_3}; margin-bottom: 6px;
  }}
  input[type=text], input[type=password] {{
    width: 100%; padding: 10px 12px; font-size: 14px; color: {INK};
    background: {PAPER}; border: 1px solid rgba(23,21,18,0.14);
    border-radius: 8px; margin-bottom: 16px; font-family: inherit;
    transition: border-color .15s ease, box-shadow .15s ease;
  }}
  input:focus {{
    outline: none; border-color: {Y_400};
    box-shadow: 0 0 0 3px rgba(245,178,27,0.22);
  }}
  button {{
    width: 100%; padding: 11px 14px; font-size: 14px; font-weight: 600;
    font-family: inherit; color: {INK}; background: {Y_400};
    border: 1px solid {Y_500}; border-radius: 8px; cursor: pointer;
    transition: background .15s ease;
  }}
  button:hover {{ background: {Y_500}; }}
  button.plain {{
    background: transparent; border-color: rgba(23,21,18,0.16); color: {INK_3};
    margin-top: 10px; font-weight: 500;
  }}
  button.plain:hover {{ background: rgba(23,21,18,0.04); }}
  .err {{
    background: rgba(217,45,32,0.07); border: 1px solid rgba(217,45,32,0.25);
    color: {CRITICAL}; border-radius: 8px; padding: 9px 12px; font-size: 13px;
    margin-bottom: 18px;
  }}
  .note {{ color: {INK_3}; font-size: 12px; margin-top: 18px; line-height: 1.55; }}
  code {{
    background: {SIDEBAR_BG}; color: {SIDEBAR_FG}; border-radius: 5px;
    padding: 2px 6px; font-size: 12px;
    font-family: 'SF Mono', ui-monospace, Menlo, Consolas, monospace;
  }}
  a {{ color: {Y_700}; }}
"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{title} · HydraPoT</title>"
            f"<link rel=icon href='/assets/favicon.ico'>"
            f"<style>{_CSS}</style></head><body><div class=card>{body}"
            f"</div></body></html>")


_BRAND = ("<div class=brand><img src='/assets/hydrapot_logo.png' alt=''>"
          "<h1>HydraPoT</h1></div>")


def login(csrf: str, *, next_path: str = "/", error: str = "",
          attempts_left: int = None) -> str:
    """The sign-in form.

    `next_path` is echoed into a hidden field so a deep link survives the
    login. The caller is responsible for having validated it -- see
    api_server._safe_next; an unvalidated value here would make this page an
    open redirect.
    """
    err = f"<div class=err>{escape(str(error))}</div>" if error else ""
    left = ""
    if attempts_left is not None and error:
        left = (f"<div class=note>{attempts_left} attempt"
                f"{'' if attempts_left == 1 else 's'} left before this address "
                f"is locked out.</div>")
    return _page("Sign in", f"""
      {_BRAND}
      <p class=sub>Operator console</p>
      {err}
      <form method=post action='/_hp/login' autocomplete=on>
        <input type=hidden name=csrf_token value='{_attr(csrf)}'>
        <input type=hidden name=next value='{_attr(next_path)}'>
        <label for=username>Operator</label>
        <input id=username name=username type=text autocomplete=username
               autofocus required>
        <label for=password>Password</label>
        <input id=password name=password type=password
               autocomplete=current-password required>
        <button type=submit>Sign in</button>
      </form>
      {left}
    """)


def locked(minutes: int) -> str:
    """Shown instead of the form while an address is locked out. Deliberately
    says nothing about whether the username was real."""
    return _page("Locked out", f"""
      {_BRAND}
      <p class=sub>Operator console</p>
      <div class=err>Too many failed sign-ins from this address.</div>
      <div class=note>Try again in up to {minutes} minutes. If this was you,
      the wait is the whole point -- it is what stops a password being guessed
      at machine speed.</div>
    """)


def no_account() -> str:
    """Served in place of the entire dashboard until an account exists.

    Not a "create your account" form: a web-based first-run setup hands the
    account to whoever reaches the port first. The CLI is already an
    authenticated channel, so it is the one that creates the account.
    """
    return _page("Setup required", f"""
      {_BRAND}
      <p class=sub>Operator console</p>
      <div class=err>No operator account exists yet.</div>
      <div class=note>
        The dashboard shows captured credentials and runs a SQL console over
        them, so it will not serve anything until there is an account to sign
        in as. Create one on the sensor host:
        <p><code>hp --dashboard-passwd</code></p>
        Accounts are created from the command line on purpose. A setup page
        served here would belong to whoever opened it first.
      </div>
    """)


def confirm_logout(csrf: str, username: str) -> str:
    """A POST is what actually signs out; this page exists to carry the CSRF
    token for it. A plain GET /logout link would let any page on the internet
    sign you out by embedding an image."""
    return _page("Sign out", f"""
      {_BRAND}
      <p class=sub>Signed in as {escape(str(username))}</p>
      <form method=post action='/_hp/logout'>
        <input type=hidden name=csrf_token value='{_attr(csrf)}'>
        <button type=submit>Sign out</button>
      </form>
      <form method=get action='/'>
        <button class=plain type=submit>Back to dashboard</button>
      </form>
    """)


def signed_out() -> str:
    return _page("Signed out", f"""
      {_BRAND}
      <p class=sub>Session ended</p>
      <div class=note>This session has been revoked -- its cookie is no longer
      accepted even if it is replayed.</div>
      <form method=get action='/_hp/login'>
        <button type=submit>Sign in again</button>
      </form>
    """)
