# """
# evaluation/eval_ondevice.py
# ─────────────────────────────────────────────────────────────────
# Evaluates On-Device LLM responses against ground truth dataset.

# Sampling strategy (handles class imbalance):
#   - FI 0 → capped at FI0_LIMIT (default 50)
#   - FI 1 → ALL commands (only ~7)
#   - FI 2 → ALL commands (only ~19)
#   - FI 3 → ALL commands (only ~57)
#   - FI 4 → ALL commands (0 in current dataset)

# Run:
#   cd evaluation
#   python eval_ondevice.py
# ─────────────────────────────────────────────────────────────────
# """

# import sys
# import os
# import json

# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# from agent_manager.ondevice_agent import OnDeviceAgent
# from computation_cost import measure_gflops, measure_latency, snapshot_before, snapshot_after
# from dataset_loader import load_eval_commands
# from fi_manager import FIScorer, FI_LABELS



# def build_eval_prompt(cmd: str, instruction: str) -> str:
#     return f"$ {cmd}"

# # ─── Config ───────────────────────────────────────────────────────────────────
# OUTPUT_FILE = "eval_ondevice_results_new_model.json"
# FI0_LIMIT = None  


# SKIP_CMDS = {
#     'ping', 'traceroute', 'top', 'watch',
#     'adduser', 'useradd', 'passwd', 'userdel',
#     'vim', 'vi', 'nano', 'less', 'more',
#     'ssh', 'telnet', 'ftp',
# }

# scorer = FIScorer()

# def sample_commands(commands: list) -> list:
#     fi0, fi_rest = [], []
#     skipped_count = 0

#     for entry in commands:
#         cmd = entry["cmd"].strip()
#         cmd_base = cmd.split()[0] if cmd else ""

#         # ADD THIS: Skip logic
#         if cmd_base in SKIP_CMDS:
#             skipped_count += 1
#             continue

#         fi, _ = scorer.score(cmd)
#         entry["_fi"] = fi  
#         if fi == 0:
#             fi0.append(entry)
#         else:
#             fi_rest.append(entry)

#     fi0_sampled = fi0 if FI0_LIMIT is None else fi0[:FI0_LIMIT]

#     print(f"\n  Sampling strategy (with Skipping):")
#     print(f"    Skipped (Blacklisted): {skipped_count}")
#     print(f"    FI 0  : {len(fi0)} total → using {len(fi0_sampled)} (capped at {FI0_LIMIT})")
#     print(f"    FI 1+ : {len(fi_rest)} total → using ALL {len(fi_rest)}")

#     merged = fi0_sampled + fi_rest
#     # Re-sort to maintain original sequence order
#     merged.sort(key=lambda e: commands.index(e))
#     return merged

# # ─── Main Eval ────────────────────────────────────────────────────────────────

# def run():
#     all_commands = load_eval_commands(limit=None)   
#     commands     = sample_commands(all_commands)
#     total        = len(commands)

#     agent   = OnDeviceAgent()
#     results = []

#     print(f"\n{'#':<5} {'CMD':<35} {'LATENCY':>10}  {'IN':>6} {'OUT':>6}  {'FI':>4}")
#     print("─" * 75)

#     for i, entry in enumerate(commands, start=1):
#         cmd          = entry["cmd"]
#         ground_truth = entry["ground_truth"]
#         instruction  = entry["instruction"]
#         fi           = entry["_fi"]
        
#         prompt = build_eval_prompt(cmd, instruction)

#         gflops = measure_gflops(agent.model, agent.tokenizer, prompt)
#         before = snapshot_before()

#         response, latency_ms = measure_latency(agent.send, prompt)

#         out_tokens = len(agent.tokenizer.encode(response))
#         memory     = snapshot_after(before)

#         results.append({
#             "index":         i,
#             "cmd":           cmd,
#             "instruction":   instruction,
#             "prompt":        prompt,
#             "ground_truth":  ground_truth,
#             "ondevice_output": response,
#             "latency_ms":    latency_ms,
#             "in_tokens":     len(agent.tokenizer.encode(prompt)),
#             "out_tokens":    out_tokens,
#             "gflops":        gflops,
#             **memory,
#             "skipped":       False,
#             "fi":            fi,            # Re-enabled these for the splitter
#             "fi_label":      FI_LABELS[fi], # Re-enabled these for the splitter
#         })

#         # Save results every iteration
#         with open(OUTPUT_FILE, "w") as f:
#             json.dump(results, f, indent=2)

#         short_cmd = (cmd[:32] + "..") if len(cmd) > 34 else cmd
#         print(f"{i:<5} {short_cmd:<35} {round(latency_ms):>8}ms  {results[-1]['in_tokens']:>6} {out_tokens:>6}  FI{fi}")



# if __name__ == "__main__":
#     run()
import sys
import os
import json
import time
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent_manager.ondevice_agent import OnDeviceAgent
from prompt_manager import PromptManager
from computation_cost import measure_gflops, measure_latency, snapshot_before, snapshot_after
from fi_manager import FILogManager, FIScorer

# ─── Config ───────────────────────────────────────────────────────────────────
CYBERLAB_FILE = "/mnt/data-partition/honeypot/cyberlab_2019-05-13.json"
BASE_DIR      = "/mnt/data-partition/honeypot/evaluation"
INTERACT_DIR  = os.path.join(BASE_DIR, "ondevice_interaction_mode")
os.makedirs(INTERACT_DIR, exist_ok=True)

MAX_SESSIONS = 10

# ─── JSON Extractor ───────────────────────────────────────────────────────────
def extract_json(text):
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return json.loads(text)
    except:
        return None

# ─── Load CyberLab Sessions ──────────────────────────────────────────────────
def load_interaction_data():
    if not os.path.exists(CYBERLAB_FILE):
        return []
    with open(CYBERLAB_FILE) as f:
        data = json.load(f)

    session_list = []
    for entry in data:
        for sid, events in entry.items():
            cmds = [e.get("message", "").split("Command found:")[-1].strip()
                    for e in events if e.get("eventid") == "cowrie.command.success"]
            if cmds:
                session_list.append({"session_id": sid, "commands": cmds})
    return session_list[:MAX_SESSIONS]

# ─── Main Execution ───────────────────────────────────────────────────────────
def run():
    agent    = OnDeviceAgent()
    sessions = load_interaction_data()
    run_id   = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"🚀 ON-DEVICE INTERACTION MODE: Using HoneyGPT Prompting")

    for s_idx, session in enumerate(sessions, start=1):
        sid  = session["session_id"]
        cmds = session["commands"]

        # ── Per-session state ─────────────────────────────────────────────────
        system_state = {"versions": {}, "installed": []}
        fi_scorer    = FIScorer()                          # no file I/O, scoring only
        fi_manager   = FILogManager.__new__(FILogManager)  # bypass __init__
        fi_manager.scorer  = fi_scorer
        fi_manager.pruner  = __import__('fi_manager').MemoryPruner(max_events=10, min_fi=2)

        pm           = PromptManager(fi_manager, system_state)
        out_file     = os.path.join(INTERACT_DIR, f"{run_id}_{sid}.json")  # ← single file
        # ─────────────────────────────────────────────────────────────────────

        session_results = []
        print(f"\n[Session {s_idx}] ID: {sid} | Commands: {len(cmds)}")

        for i, cmd in enumerate(cmds, start=1):
            # Build the HoneyGPT prompt (P, S, Qi, SRi, Hi)
            sys_p, usr_p = pm.build_prompt(cmd)          # ← fixed: unpack tuple

            # Measure & Generate
            full_prompt = usr_p   # sys_p goes to system role separately, log only user prompt
            gflops      = measure_gflops(agent.model, agent.tokenizer, full_prompt)
            before      = snapshot_before()

            raw_response, latency_ms = measure_latency(agent.send, sys_p, usr_p)  # ← fixed: pass both
            mem = snapshot_after(before)

            # Parse Ai, Ci, Fi from LLM response
            ai     = raw_response                  # plain terminal output — no JSON needed
            ci     = None
            fi, _  = fi_scorer.score(cmd)          # hardcoded FI rules, no LLM needed

            # Score FI + feed into pruner buffer (no file write)
            fi, _ = fi_scorer.score(cmd)
            fi_manager.pruner.add({
                "session_id": sid,
                "timestamp":  time.time(),
                "datetime":   datetime.now().isoformat(),
                "command":    cmd,
                "output":     ai[:300],
                "agent":      "on_device",
                "fi":         fi,
            })

            # Update system_state so next prompt gets correct SRi
            if re.search(r'(apt install|apt-get install)', cmd):
                pkg = cmd.strip().split()[-1]
                if pkg not in system_state["installed"]:
                    system_state["installed"].append(pkg)
            tool_match = re.match(r'^(\w+)\s+--version', cmd.strip())
            if tool_match:
                tool = tool_match.group(1)
                ver_match = re.search(r'(\d+\.\d+[\.\d]*)', ai)
                if tool not in system_state["versions"]:
                    system_state["versions"][tool] = ver_match.group(1) if ver_match else "unknown"

            # Log result
            result_entry = {
                "session_id":      sid,
                "index":           i,
                "cmd":             cmd,
                "response_ai":     ai,
                "state_change_ci": ci,
                "impact_fi":       fi,
                "prompt_sent":     full_prompt,
                "latency_ms":      latency_ms,
                "in_tokens":       len(agent.tokenizer.encode(full_prompt)),
                "out_tokens":      len(agent.tokenizer.encode(raw_response)),
                "gflops":          gflops,
                **mem
            }
            session_results.append(result_entry)
            print(f"  ({i}/{len(cmds)}) FI:{fi} | Latency: {latency_ms}ms | State: {ci}")

        # Save session log
        with open(out_file, "w") as f:
            json.dump(session_results, f, indent=2)

if __name__ == "__main__":
    run()