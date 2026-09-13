"""
SIEM/pages/assistant.py — the AI analyst chat widget.

A floating button, bottom-right, that opens a small chat panel. Mounted in the
app shell rather than on one page, so it stays put while you navigate and its
conversation survives moving between Summary and Investigation -- an assistant
you have to re-open and re-explain yourself to is one nobody uses.

RENDERING ONLY. The reasoning lives in api/assistant.py, which reaches HydraPoT
through the same read-only service functions the REST API exposes. This file
draws messages and forwards a question.

SHOWS ITS WORK. Every answer lists the tools that produced it. That is not
decoration: it is how you check the reply came from HydraPoT's pipeline and not
from the model's priors. An answer with no tool calls is a claim with no
evidence, and it looks like one.
"""
from dash import html, dcc, Input, Output, State, ctx, ALL
from dash.exceptions import PreventUpdate

from SIEM.server import app

# What the panel offers before you have typed anything. Chosen to demonstrate
# the range -- a roll-up, a consequence question, and a pivot -- rather than to
# look impressive.
SUGGESTIONS = [
    "What's happening right now?",
    "What is the most severe finding, and what would it have done to a real server?",
    "Which ATT&CK techniques were observed?",
]

MAX_HISTORY = 20        # turns kept in the browser store


def _enabled() -> bool:
    """Whether to offer the input at all.

    A box you can type into that then refuses to answer is worse than a
    disabled one: it invites the effort before revealing it was pointless.
    """
    try:
        from api.assistant import is_available
        return is_available()
    except Exception:
        return False


def _bubble(role: str, text: str, tools=None):
    if role == "user":
        return html.Div(text, className="ai-msg ai-msg-user")
    body = [dcc.Markdown(text, className="ai-md", link_target="_blank")]
    if tools:
        # Named, not counted: "looked up 3 things" is unverifiable, while
        # "list_detections, investigate_alert" can be checked against the API.
        body.append(html.Div(
            [html.Span("evidence from ", className="ai-tools-l"),
             html.Span(", ".join(dict.fromkeys(t["tool"] for t in tools)))],
            className="ai-tools"))
    return html.Div(body, className="ai-msg ai-msg-bot")


def _opening():
    """What the panel shows before the first question.

    A STATIC greeting, not a model call: it is instant, costs nothing, and says
    the same thing every time. Spending a round-trip and a few cents to have an
    LLM improvise "hello" would also make the first impression the slowest part
    of the product.

    It states what HydraPoT is up front because that frames every later
    answer -- without "this is a decoy", a reader can mistake an intrusion in
    the honeypot for an intrusion in their own estate.

    With no API key configured it explains that instead, HERE rather than after
    the user types a question and waits: an unconfigured optional feature
    should announce itself before it wastes anyone's time.
    """
    from api.assistant import GREETING, is_available, unavailable_message
    if not is_available():
        return [html.Div(dcc.Markdown(unavailable_message(), className="ai-md"),
                         className="ai-msg ai-msg-bot ai-msg-off")]
    return [
        _bubble("assistant", GREETING),
        html.Div(className="ai-empty", children=[
            html.Div([html.Button(s, className="ai-chip", n_clicks=0,
                                  id={"type": "ai-suggest", "q": s})
                      for s in SUGGESTIONS], className="ai-chips"),
        ]),
    ]


def _thinking():
    return html.Div(html.Div(className="ai-dots", children=[
        html.Span(), html.Span(), html.Span()]),
        className="ai-msg ai-msg-bot ai-thinking")


def widget():
    """The floating button plus the (initially hidden) panel."""
    return html.Div(id="ai-widget", children=[
        dcc.Store(id="ai-history", data=[]),
        dcc.Store(id="ai-pending", data=None),

        html.Div(id="ai-panel", className="ai-panel", hidden=True, children=[
            html.Div(className="ai-head", children=[
                html.Div(className="ai-head-t", children=[
                    html.Span("HydraPoT Security Analyst", className="ai-title"),
                    html.Span("Are you SOC?, Lemme help you!",
                              className="ai-sub"),
                ]),
                html.Button("✕", id="ai-close", className="ai-x", n_clicks=0),
            ]),
            html.Div(id="ai-log", className="ai-log", children=_opening()),
            html.Div(className="ai-input", children=[
                dcc.Input(id="ai-q", type="text", debounce=True,
                          disabled=not _enabled(),
                          placeholder=("Ask a question…" if _enabled()
                                       else "Add an API key to enable"),
                          className="ai-field"),
                html.Button("Send", id="ai-send", className="ai-send",
                            disabled=not _enabled(), n_clicks=0),
            ]),
        ]),

        html.Button(id="ai-fab", className="ai-fab", n_clicks=0, children=[
            html.Span("✦", className="ai-fab-icon"),
        ], title="Ask the security analyst"),
    ])


# ── open / close ────────────────────────────────────────────────────────────

@app.callback(
    Output("ai-panel", "hidden"),
    Input("ai-fab", "n_clicks"),
    Input("ai-close", "n_clicks"),
    State("ai-panel", "hidden"),
    prevent_initial_call=True,
)
def _toggle(_open, _close, hidden):
    """`hidden` rather than display:none via style: the property is what Dash
    and the reset stylesheet already agree on, and toggling one boolean avoids
    two callbacks fighting over the same style dict."""
    if ctx.triggered_id == "ai-close":
        return True
    return not hidden


# ── ask ─────────────────────────────────────────────────────────────────────
# Two callbacks on purpose. The first paints the question and a thinking
# indicator IMMEDIATELY; the second does the slow model call. One callback
# would leave the panel frozen with no feedback for however long the model
# takes, which reads as a broken button.

@app.callback(
    Output("ai-log", "children"),
    Output("ai-pending", "data"),
    Output("ai-q", "value"),
    Input("ai-send", "n_clicks"),
    Input("ai-q", "n_submit"),
    Input({"type": "ai-suggest", "q": ALL}, "n_clicks"),
    State("ai-q", "value"),
    State("ai-history", "data"),
    prevent_initial_call=True,
)
def _submit(_click, _enter, _chips, question, history):
    trig = ctx.triggered_id
    if isinstance(trig, dict) and trig.get("type") == "ai-suggest":
        # A pattern Input also fires on component CREATION with n_clicks=0, so
        # a real click has to be confirmed by value -- otherwise rendering the
        # suggestion chips would ask all three questions by itself.
        if not (ctx.triggered and ctx.triggered[0].get("value")):
            raise PreventUpdate
        question = trig.get("q")
    question = (question or "").strip()
    if not question:
        raise PreventUpdate

    log = [_bubble(t["role"], t["content"], t.get("tools"))
           for t in (history or [])]
    log += [_bubble("user", question), _thinking()]
    return log, question, ""


@app.callback(
    Output("ai-log", "children", allow_duplicate=True),
    Output("ai-history", "data"),
    Output("ai-pending", "data", allow_duplicate=True),
    Input("ai-pending", "data"),
    State("ai-history", "data"),
    prevent_initial_call=True,
)
def _answer(question, history):
    """The slow half: one model turn, which may make several tool calls.

    Blocking is acceptable here -- Dash serves callbacks from a thread pool, so
    one pending question does not stall the dashboard -- but it is why the
    thinking indicator is painted by a separate callback first.
    """
    if not question:
        raise PreventUpdate
    history = list(history or [])

    from api.assistant import ask
    result = ask(question, history)

    if result.get("unavailable"):
        # Not an error -- an unconfigured optional feature. Rendered as the
        # same explanation the panel shows on open.
        answer, tools = result["answer"], []
    elif result.get("error"):
        # Shown as a message rather than swallowed: a silent non-answer is
        # indistinguishable from the model deciding not to reply.
        answer = f"**Could not answer.** {result['error']}"
        tools = []
    else:
        answer = result["answer"] or "_No answer returned._"
        tools = result["tools"]

    history.append({"role": "user", "content": question})
    history.append({"role": "assistant", "content": answer, "tools": tools})
    history = history[-MAX_HISTORY:]

    log = [_bubble(t["role"], t["content"], t.get("tools")) for t in history]
    return log, history, None
