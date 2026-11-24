"""
hydrasentinel/login_page.py — the sign-in, sign-out and no-account pages.

PLAIN HTML, NOT DASH, on purpose. A Dash login page would need the session gate
to let `/_dash-update-component` through so the form's callbacks could fire --
and that endpoint is what serves every chart's data. The gate would have a hole
in exactly the shape of the thing it protects. Hand-written HTML has no
callbacks, so the gate stays closed around the whole Dash app.

Colors are imported from hydrasentinel/theme.py rather than restated, so the login
page cannot drift from the dashboard it fronts.
"""
from html import escape

from hydrasentinel.theme import (CARD, CRITICAL, INK, INK_3, PAPER, SIDEBAR_BG,
                           SIDEBAR_FG, Y_50, Y_300, Y_400, Y_500, Y_700)


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
    display: flex; overflow: hidden;
  }}
  /* split screen: circle animation on the LEFT, sign-in form on the RIGHT */
  /* NO separate panel background -- the whole page is one colour ({PAPER}) */
  .left {{ flex: 1 1 46%; min-height: 100vh; position: relative;
           overflow: hidden; display: flex;
           align-items: center; justify-content: center; }}
  .right {{ flex: 1 1 54%; min-height: 100vh; display: flex;
            align-items: center; justify-content: center; padding: 32px; }}
  @media (max-width: 860px) {{ .left {{ display: none; }} }}
  .card {{
    width: 100%; max-width: 460px; background: {CARD}; border-radius: 16px;
    border: 1px solid rgba(23,21,18,0.08);
    box-shadow: 0 1px 2px rgba(23,21,18,0.04), 0 16px 40px rgba(23,21,18,0.08);
    padding: 44px 44px;
    position: relative; z-index: 1;
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

  /* --- motion. `pop` uses the overshoot easing straight from the PSU site's
     own CSS (cubic-bezier(.34,1.56,.64,1)) -- that bounce past 1.0 is the
     "cartoon" pop. pulse-ring is the PSU radar ring, verbatim. --- */
  @keyframes rise       {{ 0%  {{ opacity: 0; transform: translateY(10px); }} }}
  @keyframes pop        {{ 0%  {{ opacity: 0; transform: scale(.3); }}
                           100% {{ opacity: 1; transform: scale(1); }} }}
  @keyframes bob        {{ 50% {{ transform: translateY(-9px); }} }}
  @keyframes hero-spin  {{ to  {{ transform: rotate(1turn); }} }}
  @keyframes orbit-rev  {{ to  {{ transform: rotate(-1turn); }} }}
  @keyframes pulse-ring {{ to  {{ opacity: 0; transform: scale(2.6); }} }}
  @keyframes twinkle    {{ 0%, 100% {{ opacity: 1; }}
                           50% {{ opacity: .5; transform: scale(.5); }} }}
  @keyframes fade       {{ from {{ opacity: 0; }} }}
  @keyframes underline-in {{ to {{ background-size: 100% 100%; }} }}

  /* the LEFT stage: concentric dashed orbits + circular MITRE/IOC nodes
     that pop in with a bounce, then gently bob. No gradients. */
  .stage {{ position: relative; width: 520px; height: 520px; max-width: 88vw;
            animation: fade .7s ease-out both; }}
  .orbit {{ position: absolute; top: 50%; left: 50%; border-radius: 50%;
            transform: translate(-50%, -50%);
            border: 1px dashed rgba(245,178,27,0.22); }}
  .orbit.o1 {{ width: 520px; height: 520px;
               animation: hero-spin 60s linear infinite; }}
  .orbit.o2 {{ width: 360px; height: 360px; border-color: rgba(245,178,27,0.14);
               animation: hero-spin 42s linear infinite reverse; }}

  /* each node rides a .sat that revolves around the centre; .ncontent
     counter-rotates so the label stays upright. All one colour. The inline
     rotate() on .sat is the resting position when motion is reduced. */
  /* small, quiet satellites -- they support the hero, they don't compete */
  .sat {{ position: absolute; top: 50%; left: 50%; width: 380px; height: 380px;
          margin: -190px; border-radius: 50%;
          animation: hero-spin 30s linear infinite; }}
  .node {{ position: absolute; top: -34px; left: 50%; margin-left: -34px;
           width: 68px; height: 68px; border-radius: 50%; display: grid;
           place-items: center; text-align: center; line-height: 1.1;
           color: {INK}; opacity: 0; background: {CARD};
           border: 1.5px solid rgba(245,178,27,0.55);
           box-shadow: 0 6px 16px rgba(23,21,18,0.08);
           animation: pop .55s cubic-bezier(.34,1.56,.64,1) var(--delay,0s) forwards; }}
  .ncontent {{ animation: orbit-rev 30s linear infinite; }}
  .node .tag {{ font-family: 'SF Mono', ui-monospace, Menlo, Consolas, monospace;
                font-weight: 700; color: {Y_500}; font-size: 11px; }}
  .node small {{ color: {INK_3}; font-size: 8px;
                 letter-spacing: .03em; text-transform: uppercase; }}

  /* THE main character: a big HydraPoT badge, with a radar pulse-ring */
  .core {{ position: absolute; top: 50%; left: 50%; width: 248px; height: 248px;
           margin: -124px; border-radius: 50%; display: flex;
           flex-direction: column; align-items: center; justify-content: center;
           gap: 10px; text-align: center; background: {Y_400};
           color: {INK}; z-index: 2; opacity: 0;
           box-shadow: 0 26px 64px -16px rgba(245,178,27,0.75),
                       0 12px 30px rgba(23,21,18,0.18);
           animation: pop .7s cubic-bezier(.34,1.56,.64,1) .05s forwards; }}
  .core img {{ width: 76px; height: 76px; display: block; }}
  .core b {{ font-size: 26px; letter-spacing: -0.02em; line-height: 1;
             display: block; }}
  .core span {{ font-size: 10px; letter-spacing: .18em; text-transform: uppercase;
                color: {INK}; opacity: .6; line-height: 1; }}
  .core::after {{ content: ''; position: absolute; inset: 0; border-radius: 50%;
                  border: 2px solid rgba(245,178,27,0.55);
                  animation: pulse-ring 2.6s cubic-bezier(.16,1,.3,1) 1s infinite; }}

  /* cartoon dashboard-feature icons that circle the hero. .orb spins the
     ring; .bubble counter-spins (same pace) so the icon stays upright. */
  .orb {{ position: absolute; top: 50%; left: 50%; border-radius: 50%;
          animation-timing-function: linear; animation-iteration-count: infinite; }}
  .bubble {{ position: absolute; top: 0; left: 50%; width: 50px; height: 50px;
             margin: -25px 0 0 -25px; border-radius: 50%; display: grid;
             place-items: center; background: var(--c, {CARD});
             color: var(--ink, {INK});
             border: 1px solid rgba(23,21,18,0.06);
             box-shadow: 0 10px 22px rgba(23,21,18,0.16);
             animation-timing-function: linear; animation-iteration-count: infinite; }}
  .bubble svg {{ width: 25px; height: 25px; display: block;
                 animation: bob 3s ease-in-out infinite; }}

  .stage-cap {{ position: absolute; bottom: 44px; left: 0; right: 0;
                text-align: center; color: {INK_3}; font-size: 13px;
                opacity: 0; animation: rise .6s cubic-bezier(.16,1,.3,1) 1.1s both; }}
  .stage-cap b {{ color: {INK}; display: inline-block;
                  background-image: linear-gradient(transparent 70%,
                    rgba(245,178,27,0.5) 70% 92%, transparent 92%);
                  background-repeat: no-repeat; background-size: 0 100%;
                  animation: underline-in .9s cubic-bezier(.16,1,.3,1) 1.5s forwards; }}

  /* the sign-in card's own staggered entrance (right side) */
  .card > * {{ animation: rise .5s cubic-bezier(.16,1,.3,1) both;
               animation-delay: var(--delay, 0s); }}
  .brand {{ --delay: .05s; }}
  .sub   {{ --delay: .12s; }}
  form   {{ --delay: .19s; }}
  .err   {{ --delay: .14s; }}
  .note  {{ --delay: .26s; }}

  button {{ transition: background .15s ease, transform .2s ease; }}
  button:hover {{ transform: translateY(-1px); }}

  @media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{
      animation-duration: 1ms !important; animation-iteration-count: 1 !important;
    }}
    .orbit, .core::after {{ animation: none; }}
  }}
"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{title} · HydraPoT</title>"
            f"<link rel=icon href='/assets/favicon.ico'>"
            f"<style>{_CSS}</style></head><body>"
            f"<aside class=left>{_STAGE}</aside>"
            f"<div class=right><div class=card>{body}</div></div>"
            f"</body></html>")


_BRAND = ("<div class=brand><img src='/assets/hydrapot_logo.png' alt=''>"
          "<h1>HydraPoT</h1></div>")


def _ico(inner: str) -> str:
    """Wrap hand-drawn SVG path(s) in a consistent cartoon icon: rounded,
    2px stroke, inheriting the bubble's colour via currentColor."""
    return ("<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' "
            "stroke-width='2' stroke-linecap='round' stroke-linejoin='round'>"
            f"{inner}</svg>")


# Six dashboard features, each drawn by hand (no icon font, no emoji).
ICON_THREATS   = _ico("<path d='M12 3l7 3v5c0 4.2-2.9 7.4-7 9"
                      "-4.1-1.6-7-4.8-7-9V6z'/><path d='M9 12l2 2 4-4'/>")
ICON_ANALYTICS = _ico("<path d='M4 20h16'/>"
                      "<rect x='6' y='11' width='3' height='6' rx='1'/>"
                      "<rect x='11' y='6' width='3' height='11' rx='1'/>"
                      "<rect x='16' y='13' width='3' height='4' rx='1'/>")
ICON_SESSIONS  = _ico("<rect x='3' y='4' width='18' height='13' rx='2'/>"
                      "<path d='M8 20h8'/><path d='M12 17v3'/>"
                      "<path d='M7 9l2.4 2L7 13'/><path d='M12.5 13H15'/>")
ICON_GEOIP     = _ico("<circle cx='12' cy='12' r='9'/><path d='M3 12h18'/>"
                      "<path d='M12 3c2.8 2.6 2.8 15 0 18'/>"
                      "<path d='M12 3c-2.8 2.6-2.8 15 0 18'/>")
ICON_CREDS     = _ico("<rect x='5' y='10' width='14' height='10' rx='2'/>"
                      "<path d='M8 10V7a4 4 0 0 1 8 0v3'/>"
                      "<circle cx='12' cy='15' r='1.4'/>")
ICON_ALERTS    = _ico("<path d='M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6'/>"
                      "<path d='M10 20a2 2 0 0 0 4 0'/>")


def _orb(icon: str, bg: str, ink: str, orbit: int, spd: str, delay: str,
         rev: bool) -> str:
    """One hand-drawn dashboard icon circling the hero. `orbit` is the ring
    diameter, `spd`/`delay` set pace and starting angle, `rev` flips the
    direction. The bubble counter-spins at the same pace to stay upright."""
    half = orbit / 2
    name = "orbit-rev" if rev else "hero-spin"
    counter = "hero-spin" if rev else "orbit-rev"
    return (f"<span class=orb style='width:{orbit}px;height:{orbit}px;"
            f"margin:-{half}px;animation-name:{name};animation-duration:{spd};"
            f"animation-delay:{delay}'>"
            f"<span class=bubble style='--c:{bg};--ink:{ink};"
            f"animation-name:{counter};animation-duration:{spd};"
            f"animation-delay:{delay}'>{icon}</span></span>")


# The left stage. Static, illustrative MITRE/IOC labels -- this runs on the
# UNAUTHENTICATED login page, so it must never touch the real capture DB.
# Four nodes, one colour, evenly spaced and revolving around the centre.
_STAGE = (
    "<div class=stage>"
    "<div class='orbit o1'></div><div class='orbit o2'></div>"
    "<div class=core><img src='/assets/hydrapot_logo.png' alt=''>"
    "<b>HydraPoT</b><span>Operator console</span></div>"
    + _orb(ICON_THREATS,   "#ffe3df", "#e5484d", 300, "17s", "0s",   False)
    + _orb(ICON_ANALYTICS, "#ece2ff", "#8b5cf6", 340, "23s", "-5s",  True)
    + _orb(ICON_SESSIONS,  "#dcf5e4", "#16a34a", 300, "20s", "-9s",  False)
    + _orb(ICON_GEOIP,     "#dbe9ff", "#2f6bff", 360, "26s", "-3s",  True)
    + _orb(ICON_CREDS,     "#fbefc9", "#c98a00", 330, "19s", "-13s", False)
    + _orb(ICON_ALERTS,    "#ffe0ef", "#e0529c", 360, "29s", "-7s",  True)
    + "<div class=stage-cap>Every session mapped to <b>MITRE ATT&CK</b></div>"
    + "</div>")


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


def invite(csrf: str, token: str, username: str, *, error: str = "") -> str:
    """The page a colleague lands on from an invite link: the name is fixed by
    the invite, they choose only their own password."""
    err = f"<div class=err>{escape(str(error))}</div>" if error else ""
    # A named invite fixes the name; an open one (username "") lets the visitor choose.
    name_field = (f"<input id=username type=text value='{_attr(username)}' readonly>"
                  if username else
                  "<input id=username name=username type=text autocomplete=off "
                  "placeholder='3-32 letters, digits, . _ -' autofocus required>")
    return _page("Accept invite", f"""
      {_BRAND}
      <p class=sub>You have been invited to the operator console</p>
      {err}
      <form method=post action='/_hp/invite/{_attr(token)}' autocomplete=off>
        <input type=hidden name=csrf_token value='{_attr(csrf)}'>
        <label for=username>Operator</label>
        {name_field}
        <label for=password>Choose a password</label>
        <input id=password name=password type=password
               autocomplete=new-password required>
        <label for=again>Password again</label>
        <input id=again name=again type=password
               autocomplete=new-password required>
        <button type=submit>Create my account</button>
      </form>
    """)


def invite_invalid() -> str:
    """Unknown, used and expired links all read the same."""
    return _page("Invite not valid", f"""
      {_BRAND}
      <p class=sub>Operator console</p>
      <div class=err>This invite link is not valid.</div>
      <div class=note>It may have been used already or have expired. Ask whoever
      runs this sensor for a new one.</div>
    """)
