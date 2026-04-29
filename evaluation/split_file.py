"""
evaluation/dataset_splitter.py
─────────────────────────────────────────────────────────────────
Reads eval_ondevice_results_new_model.json and produces:

  1. AI reliability test dataset/
       batch_01.json ... batch_N.json  (50 entries each)
       Each entry: { cmd, ground_truth, response, fi, fi_label }
       → rate response 1-5 vs ground_truth to measure trust

  2. new_model_dataset/
       new_model_full.json
       Each entry: { cmd, ondevice_output, fi, fi_label }
       → clean LLM output only, no ground truth / latency

Run:
  cd /mnt/data-partition/honeypot/evaluation
  python dataset_splitter.py
─────────────────────────────────────────────────────────────────
"""

import json
import os
import math
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fi_manager import FIScorer, FI_LABELS
# ── paths ─────────────────────────────────────────────────────────────────────
BASE_DIR         = "/mnt/data-partition/honeypot/evaluation"
INPUT_FILE       = os.path.join(BASE_DIR, "eval_ondevice_results_new_model.json")
COWRIE_FILE      = os.path.join(BASE_DIR, "eval_cowrie_results.json")
RELIABILITY_DIR  = os.path.join(BASE_DIR, "AI reliability test dataset")
NEW_MODEL_DIR    = os.path.join(BASE_DIR, "new_model_dataset")
COWRIE_DIR       = os.path.join(BASE_DIR, "cowrie_dataset")
BATCH_SIZE       = 50

# ── load ──────────────────────────────────────────────────────────────────────
print(f"Loading {INPUT_FILE} ...")
with open(INPUT_FILE, "r") as f:
    data = json.load(f)
print(f"  → {len(data)} entries loaded")

# ── split by FI level ─────────────────────────────────────────────────────────
fi0_data   = [e for e in data if e.get("fi", 0) == 0]
fi1_4_data = [e for e in data if e.get("fi", 0) in (1, 2, 3, 4)]
print(f"  → FI 0: {len(fi0_data)} entries")
print(f"  → FI 1-4: {len(fi1_4_data)} entries")

# ── make output dirs ──────────────────────────────────────────────────────────
os.makedirs(RELIABILITY_DIR, exist_ok=True)
os.makedirs(NEW_MODEL_DIR,   exist_ok=True)
os.makedirs(COWRIE_DIR,      exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1. AI RELIABILITY TEST DATASET
#    fields: cmd, ground_truth, response, fi, fi_label
#    split into batches of 50
# ─────────────────────────────────────────────────────────────────────────────
reliability_entries = [
    {
        "cmd":      entry["cmd"],
        "response": entry["ground_truth"],   # ground truth posed as system response
    }
    for entry in data
]

# FI 0 and FI 1-4 as separate entry lists
rel_fi0   = [e for e in reliability_entries if data[reliability_entries.index(e)].get("fi", 0) == 0]
rel_fi1_4 = [e for e in reliability_entries if data[reliability_entries.index(e)].get("fi", 0) in (1, 2, 3, 4)]

def write_batches(entries, prefix, label):
    n = math.ceil(len(entries) / BATCH_SIZE)
    print(f"\n  [{label}] {len(entries)} entries → {n} batches of {BATCH_SIZE}")
    for b in range(n):
        start = b * BATCH_SIZE
        end   = start + BATCH_SIZE
        batch = entries[start:end]
        filename = os.path.join(RELIABILITY_DIR, f"{prefix}_batch_{b+1:02d}.json")
        with open(filename, "w") as f:
            json.dump(batch, f, indent=2)
        print(f"    ✓ {os.path.basename(filename)}  ({len(batch)} entries, index {start+1}–{min(end, len(entries))})")
    return n

print(f"\n[1] AI reliability test dataset")
n_fi0   = write_batches(rel_fi0,   "fi0",   "FI 0")
n_fi1_4 = write_batches(rel_fi1_4, "fi1_4", "FI 1-4")

# ─────────────────────────────────────────────────────────────────────────────
# 2. NEW MODEL DATASET
#    fields: cmd, ondevice_output, fi, fi_label  (no ground truth, no latency)
# ─────────────────────────────────────────────────────────────────────────────
new_model_entries = [
    {
        "cmd":             entry["cmd"],
        "ondevice_output": entry["ondevice_output"],
    }
    for entry in data
]

nm_fi0   = [e for e in new_model_entries if data[new_model_entries.index(e)].get("fi", 0) == 0]
nm_fi1_4 = [e for e in new_model_entries if data[new_model_entries.index(e)].get("fi", 0) in (1, 2, 3, 4)]

def write_batches_to_folder(entries, prefix, label, output_dir):
    n = math.ceil(len(entries) / BATCH_SIZE)
    print(f"\n  [{label}] {len(entries)} entries → {n} batches of {BATCH_SIZE}")
    for b in range(n):
        start = b * BATCH_SIZE
        end   = start + BATCH_SIZE
        batch = entries[start:end]
        # Use output_dir instead of a hardcoded variable
        filename = os.path.join(output_dir, f"{prefix}_batch_{b+1:02d}.json")
        with open(filename, "w") as f:
            json.dump(batch, f, indent=2)
        print(f"    ✓ {os.path.basename(filename)}  ({len(batch)} entries)")
    return n
print(f"\n[2] new_model_dataset")
n_nm_fi0   = write_batches_to_folder(nm_fi0,   "fi0",   "FI 0", NEW_MODEL_DIR)
n_nm_fi1_4 = write_batches_to_folder(nm_fi1_4, "fi1_4", "FI 1-4", NEW_MODEL_DIR)

scorer = FIScorer()

# ─────────────────────────────────────────────────────────────────────────────
# 3. COWRIE DATASET (With On-the-Fly FI Scoring)
# ─────────────────────────────────────────────────────────────────────────────
print(f"\nLoading {COWRIE_FILE} ...")
with open(COWRIE_FILE, "r") as f:
    cowrie_data = json.load(f)
print(f"  → {len(cowrie_data)} entries loaded")

cow_fi0 = []
cow_fi1_4 = []

print("  → Scoring commands and sorting...")

for entry in cowrie_data:
    if entry.get("skipped", False):
        continue
    
    cmd_text = entry.get("cmd", "")
    # Use your FIScorer to get the level
    fi_val, _ = scorer.score(cmd_text)
    
    formatted = {
        "cmd":      cmd_text,
        "response": entry.get("cowrie_output", ""),
    }
    
    # Sort based on the score we just generated
    if fi_val == 0:
        cow_fi0.append(formatted)
    elif fi_val in (1, 2, 3, 4):
        cow_fi1_4.append(formatted)

# Now call the batch writer
print(f"\n[3] cowrie_dataset")
n_cow_fi0   = write_batches_to_folder(cow_fi0,   "fi0",   "FI 0", COWRIE_DIR)
n_cow_fi1_4 = write_batches_to_folder(cow_fi1_4, "fi1_4", "FI 1-4", COWRIE_DIR)


COMMAND_TRACK_DIR = os.path.join(BASE_DIR, "command_track")
os.makedirs(COMMAND_TRACK_DIR, exist_ok=True)

def extract_and_batch_commands(source_data, prefix, label):
    """Extracts only the 'cmd' field and saves in batches of 50."""
    # Filter and format: only keep the command string
    command_only_list = [{"cmd": e["cmd"]} for e in source_data]
    
    n = math.ceil(len(command_only_list) / BATCH_SIZE)
    print(f"\n  [Command Track - {label}] {len(command_only_list)} commands → {n} batches")
    
    for b in range(n):
        start = b * BATCH_SIZE
        end   = start + BATCH_SIZE
        batch = command_only_list[start:end]
        
        filename = os.path.join(COMMAND_TRACK_DIR, f"{prefix}_cmd_batch_{b+1:02d}.json")
        with open(filename, "w") as f:
            json.dump(batch, f, indent=2)
        print(f"    ✓ {os.path.basename(filename)} ({len(batch)} commands)")

print(f"\n[4] Generating Command Track (Commands Only)")
# Using the filtered lists you already created (fi0_data and fi1_4_data)
extract_and_batch_commands(fi0_data,   "fi0",   "FI 0")
extract_and_batch_commands(fi1_4_data, "fi1_4", "FI 1-4")