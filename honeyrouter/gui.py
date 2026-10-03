"""
honeyrouter/gui.py — a small local web GUI to SET UP, TRAIN and REVIEW the
HoneyRouter. Styled as a compact window-like card (Models / Train / Review).

  MODELS   the arms are read from config.yaml (config_loader). You can also
           register an extra model (name + cost) for future use -- register-only
           for now; its identity vector (B.3.4 quizzing) is wired in later.
  TRAIN    one click runs Phase 1 -> 2 -> 3 as live subprocesses; a single green
           0-100% bar spans all phases (parsed from each phase's ep/step output).
  REVIEW   shows what the trained router DECIDES -- routing mix across the
           preference sweep, and a per-command table (command -> chosen arm with
           the p_hat/cost behind it). "Looks good" records a note.

Local tool: binds 127.0.0.1 only. It shells out to the same scripts you run by
hand (predictor.py, routing_policy.py, reinforcement.py) with this interpreter.

NOTE: no first-run "force training" gate yet -- that logic gets wired into
production later.

    python honeyrouter/gui.py            # then open http://127.0.0.1:7861
    python honeyrouter/gui.py --port 8000
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time

from flask import Flask, jsonify, request, Response

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from honeyrouter.action import AGENTS                       # noqa: E402

OUT_DIR = os.path.join(_HERE, "out")
APPROVED = os.path.join(OUT_DIR, "approved.json")
EXTRA = os.path.join(OUT_DIR, "extra_models.json")
PY = sys.executable

app = Flask(__name__)

# ── training job state ────────────────────────────────────────────────────────
_LOCK = threading.Lock()
STATE = {"running": False, "phase": None, "log": [], "done": False,
         "error": None, "progress": 0.0, "config": None}


def _log(line: str):
    with _LOCK:
        STATE["log"].append(line.rstrip("\n"))
        if len(STATE["log"]) > 2000:
            STATE["log"] = STATE["log"][-2000:]


def _progress(pct: float):
    with _LOCK:
        STATE["progress"] = round(max(0.0, min(100.0, pct)), 1)


def _run_phase(name, cmd, idx, n, total, kind):
    with _LOCK:
        STATE["phase"] = name
    _log(f"===== {name} =====")
    pat = re.compile(rf"\b{kind}\s+(\d+)")
    proc = subprocess.Popen(cmd, cwd=_ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1,
                            env={**os.environ, "PYTHONUNBUFFERED": "1"})
    for line in proc.stdout:
        if "it/s]" in line or "Loading weights" in line:
            continue
        _log(line)
        m = pat.search(line)
        if m and total > 0:
            inner = min(1.0, int(m.group(1)) / total)
            _progress((idx + inner) / n * 100)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"{name} exited with code {proc.returncode}")
    _progress((idx + 1) / n * 100)


def _worker(cfg):
    phases = [
        ("Phase 1 · IRT predictor", cfg["p1_epochs"], "ep",
         [PY, "-u", os.path.join(_HERE, "predictor.py"),
          "--epochs", str(cfg["p1_epochs"])]),
        ("Phase 2 · policy pretraining", cfg["p2_steps"], "step",
         [PY, "-u", os.path.join(_HERE, "routing_policy.py"),
          "--steps", str(cfg["p2_steps"]), "--batch", str(cfg["p2_batch"])]),
    ]
    if cfg["run_rl"]:
        rl = [PY, "-u", os.path.join(_HERE, "reinforcement.py"),
              "--steps", str(cfg["p3_steps"])]
        if not cfg["mixup"]:
            rl.append("--no-mixup")
        phases.append(("Phase 3 · RL (multi-objective PPO)", cfg["p3_steps"],
                       "step", rl))
    n = len(phases)
    try:
        for i, (name, total, kind, cmd) in enumerate(phases):
            _run_phase(name, cmd, i, n, total, kind)
        _progress(100.0)
        _log("ALL DONE ✓")
    except Exception as e:                                   # noqa: BLE001
        with _LOCK:
            STATE["error"] = str(e)
        _log(f"ERROR: {e}")
    finally:
        with _LOCK:
            STATE["running"] = False
            STATE["done"] = True
            STATE["phase"] = None


# ── review helpers ────────────────────────────────────────────────────────────
_DATA = {}


def _load_data():
    if _DATA:
        return _DATA
    import numpy as np
    import torch
    from honeyrouter import predictor as P
    from honeyrouter import routing_policy as RP
    from honeyrouter.sessions import load_sessions
    if not os.path.exists(os.path.join(OUT_DIR, "predictor.pt")):
        return None
    model, _ = P.load()
    E, score, cost, sids, _ = RP.build_pairwise_dataset()
    sess = load_sessions()
    cmds = [c["cmd"] for _, cs in sess.items() for c in cs]
    I = model.mu.detach()
    with torch.no_grad():
        p_hat = torch.sigmoid(model.logits(torch.tensor(E), I)).numpy()
    cn = cost / np.maximum(cost.max(1, keepdims=True), 1e-8)
    _DATA.update(dict(E=E, score=score, cost=cost, cost_norm=cn, cmds=cmds,
                      I=I.numpy(), p_hat=p_hat, np=np, torch=torch))
    return _DATA


def _policy(which):
    from honeyrouter import routing_policy as RP
    if which == "phase3":
        from honeyrouter import reinforcement as RL
        if not os.path.exists(os.path.join(OUT_DIR, "routing_policy_rl.pt")):
            return None
        pol, _, _ = RL.load_rl_policy()
        return pol
    if not os.path.exists(os.path.join(OUT_DIR, "routing_policy.pt")):
        return None
    pol, _ = RP.load_policy()
    return pol


def _picks(pol, w):
    d = _load_data()
    torch = d["torch"]
    n = d["E"].shape[0]
    I = torch.tensor(d["I"])
    e = torch.tensor(d["E"])
    I_ctx = I.unsqueeze(0).expand(n, len(AGENTS), I.shape[1])
    c_ctx = torch.tensor(d["cost_norm"]).unsqueeze(-1)
    p_ctx = torch.tensor(d["p_hat"]).unsqueeze(-1)
    omega = torch.tensor([[1.0, float(w)]]).expand(n, 2)
    with torch.no_grad():
        return pol.logits(e, I_ctx, c_ctx, p_ctx, omega).argmax(1).numpy()


def _extra_models():
    if os.path.exists(EXTRA):
        try:
            return json.load(open(EXTRA))
        except Exception:                                   # noqa: BLE001
            return []
    return []


# ── HTML ──────────────────────────────────────────────────────────────────────
PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<title>HoneyRouter setup</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0f1420;--card:#182233;--ink:#e6edf7;--mut:#8ba0bd;--acc:#4da3ff;--ok:#39d98a;--bad:#ff6b6b;--line:#26344b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 system-ui,sans-serif;
display:flex;justify-content:center;padding:22px 12px}
.win{width:460px;max-width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;
box-shadow:0 12px 40px #0008}
.title{background:#111b2c;padding:10px 14px;border-bottom:1px solid var(--line);font-weight:600}
.title small{color:var(--mut);font-weight:400}
.tabs{display:flex;border-bottom:1px solid var(--line)}
.tab{flex:1;padding:9px;text-align:center;cursor:pointer;color:var(--mut);font-weight:600;font-size:12px}
.tab.on{color:var(--acc);box-shadow:inset 0 -2px 0 var(--acc)}
.pane{padding:14px}.pane.hide{display:none}
label{display:block;color:var(--mut);font-size:11px;margin:8px 0 2px}
input,select{background:#0d1526;color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:6px 8px;width:100%}
.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
button{background:var(--acc);color:#04101f;border:0;border-radius:8px;padding:9px 14px;font-weight:700;cursor:pointer}
button:disabled{opacity:.5;cursor:default}button.ok{background:var(--ok)}
.arm{display:flex;align-items:center;gap:8px;background:#0d1526;border:1px solid var(--line);border-radius:8px;padding:7px 10px;margin:5px 0}
.arm .n{font-weight:600}.arm .m{color:var(--mut);font-size:11px;margin-left:auto}
.arm input{width:auto}
.track{height:20px;background:#0d1526;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin:8px 0}
.fill{height:100%;width:0;background:linear-gradient(90deg,#2ec77a,#39d98a);transition:width .3s;
display:flex;align-items:center;justify-content:flex-end;padding-right:8px;color:#04101f;font-weight:700;font-size:11px}
pre{background:#08101e;border:1px solid var(--line);border-radius:8px;padding:9px;max-height:170px;overflow:auto;font-size:11px;white-space:pre-wrap;color:var(--mut)}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700}
.b-cowrie{background:#2b3a2b;color:#9ae6a0}.b-on_device{background:#33304a;color:#c3b6ff}.b-cloud{background:#2a3a4d;color:#8fd0ff}
table{width:100%;border-collapse:collapse;font-size:11px}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line)}
th{color:var(--mut)}.bar{height:20px;border-radius:6px;display:flex;overflow:hidden;margin:6px 0}
.seg{display:flex;align-items:center;justify-content:center;font-size:10px;color:#04101f;font-weight:700}
.muted{color:var(--mut)}.done{color:var(--ok);font-weight:600}.err{color:var(--bad);font-weight:600}
.hint{color:var(--mut);font-size:11px;margin:6px 0}
</style></head><body>
<div class=win>
<div class=title>🐝 HoneyRouter setup <small>— train once, review the rules</small></div>
<div class=tabs>
  <div class="tab on" data-t=models onclick=tab('models')>Models</div>
  <div class=tab data-t=train onclick=tab('train')>Train</div>
  <div class=tab data-t=review onclick=tab('review')>Review</div>
</div>

<div id=p-models class=pane>
  <div id=arms></div>
  <div class=hint>Arms are read from <code>config.yaml</code>. Selection is saved for when this is wired to production.</div>
  <label>Add a model for future use (register only)</label>
  <div class=row><input id=nm placeholder="name e.g. cloud_mini"><input id=cst type=number step=0.000001 placeholder="cost $/cmd"></div>
  <div style="margin-top:8px"><button class=ghost onclick=addModel()>+ Add model</button></div>
  <div id=extra class=hint></div>
</div>

<div id=p-train class="pane hide">
  <div class=row>
    <div><label>Phase 1 · epochs</label><input id=p1_epochs type=number value=10></div>
    <div><label>Phase 2 · steps</label><input id=p2_steps type=number value=500></div>
    <div><label>Phase 2 · batch</label><input id=p2_batch type=number value=1024></div>
    <div><label>Phase 3 · steps</label><input id=p3_steps type=number value=500></div>
    <div><label>Run RL (Phase 3)</label><select id=run_rl><option value=1>yes</option><option value=0>no</option></select></div>
    <div><label>Mixup</label><select id=mixup><option value=1>on</option><option value=0>off</option></select></div>
  </div>
  <div style="margin-top:12px"><button id=btn onclick=train()>Train ▶</button>
    <span id=tstate class=muted style="margin-left:8px"></span></div>
  <div class=track><div id=fill class=fill>0%</div></div>
  <pre id=log>Not started.</pre>
</div>

<div id=p-review class="pane hide">
  <div class=row>
    <div><label>Policy</label><select id=which onchange=review()><option value=phase3>Phase 3 (RL)</option><option value=phase2>Phase 2 (pretrained)</option></select></div>
    <div><label>ω (0=fidelity · 2=cheap): <span id=ov>0</span></label>
      <input id=omega type=range min=0 max=2 step=0.1 value=0 oninput="ov.textContent=this.value;review()"></div>
  </div>
  <div id=mix></div>
  <div style="max-height:230px;overflow:auto"><table id=tbl></table></div>
  <div style="margin-top:10px"><button class=ok onclick=approve()>Looks good ✓</button>
    <span id=astate class=muted style="margin-left:8px"></span></div>
</div>
</div>

<script>
const AG=%AGENTS%;
function tab(t){document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.dataset.t==t));
  ['models','train','review'].forEach(p=>document.getElementById('p-'+p).classList.toggle('hide',p!=t));
  if(t=='review')review();}
function loadCfg(){fetch('/api/config').then(r=>r.json()).then(c=>{
  document.getElementById('arms').innerHTML=c.arms.map(a=>
    `<div class=arm><input type=checkbox ${a.enabled?'checked':''}><span class=n>${a.name}</span><span class=m>${a.model} · $${a.mean_cost.toFixed(6)}</span></div>`).join('');
  document.getElementById('extra').textContent=c.extra.length?('Registered: '+c.extra.map(e=>e.name+' ($'+e.cost+')').join(', ')):'';
});}
loadCfg();
function addModel(){const name=nm.value.trim(),cost=parseFloat(cst.value||'0');if(!name)return;
  fetch('/api/add_model',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,cost})})
    .then(r=>r.json()).then(()=>{nm.value='';cst.value='';loadCfg();});}
let poll=null;
function train(){
  const cfg={p1_epochs:+p1_epochs.value,p2_steps:+p2_steps.value,p2_batch:+p2_batch.value,
    p3_steps:+p3_steps.value,run_rl:+run_rl.value,mixup:+mixup.value};
  btn.disabled=true;
  fetch('/api/train',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)})
    .then(r=>r.json()).then(()=>{if(!poll)poll=setInterval(status,800);status();});
}
function status(){fetch('/api/status').then(r=>r.json()).then(s=>{
  log.textContent=s.log.join('\n')||'starting…';log.scrollTop=1e9;
  const f=document.getElementById('fill');f.style.width=s.progress+'%';f.textContent=Math.round(s.progress)+'%';
  const t=document.getElementById('tstate');
  if(s.running){t.textContent=s.phase||'running';t.className='muted';}
  else if(s.error){t.textContent='failed';t.className='err';btn.disabled=false;clearInterval(poll);poll=null;}
  else if(s.done){t.textContent='finished ✓';t.className='done';btn.disabled=false;clearInterval(poll);poll=null;tab('review');}
});}
function review(){const w=omega.value,which=document.getElementById('which').value;
  fetch(`/api/review?omega=${w}&which=${which}`).then(r=>r.json()).then(d=>{
    if(d.error){mix.innerHTML='<span class=err>'+d.error+'</span>';tbl.innerHTML='';return;}
    const col={cowrie:'#39d98a',on_device:'#8f7bff',cloud:'#4da3ff'};
    mix.innerHTML='<div class=bar>'+AG.map(a=>{const p=d.mix[a]||0;
      return p>0?`<div class=seg style="width:${p*100}%;background:${col[a]}">${a} ${Math.round(p*100)}%</div>`:''}).join('')+'</div>';
    let h='<tr><th>command</th><th>chosen</th>'+AG.map(a=>`<th>p̂${a[0]}</th>`).join('')+'</tr>';
    d.rows.forEach(r=>{h+=`<tr><td><code>${r.cmd}</code></td><td><span class="pill b-${r.pick}">${r.pick}</span></td>`+
      r.p_hat.map(x=>`<td>${x.toFixed(2)}</td>`).join('')+'</tr>';});
    tbl.innerHTML=h;});
}
function approve(){const w=omega.value,which=document.getElementById('which').value;
  fetch('/api/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({omega:+w,which})})
    .then(r=>r.json()).then(d=>{astate.textContent='saved → '+d.path;astate.className='done';});}
</script></body></html>"""


@app.route("/")
def index():
    return Response(PAGE.replace("%AGENTS%", json.dumps(list(AGENTS))),
                    mimetype="text/html")


@app.route("/api/config")
def api_config():
    from honeyrouter import routing_policy as RP
    try:
        from core.config_loader import load_config
        cfg = load_config()
        agents = cfg.agents
    except Exception:                                       # noqa: BLE001
        agents = None
    try:
        _, _, cost, _, _ = RP.build_pairwise_dataset()
        means = cost.mean(axis=0)
    except Exception:                                       # noqa: BLE001
        means = [0.0] * len(AGENTS)
    arms = []
    for i, a in enumerate(AGENTS):
        ac = getattr(agents, a, None) if agents else None
        arms.append({"name": a,
                     "model": getattr(ac, "model", "Cowrie backend") if ac else "?",
                     "enabled": bool(getattr(ac, "enabled", True)) if ac else True,
                     "mean_cost": float(means[i])})
    return jsonify({"arms": arms, "extra": _extra_models()})


@app.route("/api/add_model", methods=["POST"])
def api_add_model():
    b = request.get_json(force=True)
    lst = _extra_models()
    lst.append({"name": b.get("name"), "cost": b.get("cost", 0.0),
                "added": time.strftime("%Y-%m-%d %H:%M")})
    os.makedirs(OUT_DIR, exist_ok=True)
    json.dump(lst, open(EXTRA, "w"), indent=2)
    return jsonify({"ok": True, "extra": lst})


@app.route("/api/train", methods=["POST"])
def api_train():
    cfg = request.get_json(force=True)
    with _LOCK:
        if STATE["running"]:
            return jsonify({"error": "already running"}), 409
        STATE.update({"running": True, "phase": None, "log": [], "done": False,
                      "error": None, "progress": 0.0, "config": cfg})
    threading.Thread(target=_worker, args=(cfg,), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    with _LOCK:
        return jsonify({k: STATE[k] for k in
                        ("running", "phase", "log", "done", "error", "progress")})


@app.route("/api/review")
def api_review():
    which = request.args.get("which", "phase3")
    w = float(request.args.get("omega", 0))
    n = int(request.args.get("n", 25))
    d = _load_data()
    if d is None:
        return jsonify({"error": "No trained model yet — train first."})
    pol = _policy(which)
    if pol is None:
        return jsonify({"error": f"{which} not found — run that phase."})
    picks = _picks(pol, w)
    total = len(picks)
    mix = {a: float((picks == i).mean()) for i, a in enumerate(AGENTS)}
    step = max(1, total // n)
    rows = []
    for r in range(0, total, step):
        rows.append({"cmd": d["cmds"][r][:56], "pick": AGENTS[int(picks[r])],
                     "p_hat": [float(x) for x in d["p_hat"][r]]})
        if len(rows) >= n:
            break
    return jsonify({"mix": mix, "rows": rows})


@app.route("/api/approve", methods=["POST"])
def api_approve():
    b = request.get_json(force=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    rec = {"approved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
           "policy": b.get("which"), "omega": b.get("omega"),
           "config": STATE.get("config")}
    json.dump(rec, open(APPROVED, "w"), indent=2)
    return jsonify({"ok": True, "path": os.path.relpath(APPROVED, _ROOT)})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7861)
    a = ap.parse_args()
    print(f"HoneyRouter GUI -> http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()
