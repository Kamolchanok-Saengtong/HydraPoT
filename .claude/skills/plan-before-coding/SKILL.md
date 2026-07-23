---
name: plan-before-coding
description: MANDATORY workflow for the HydraPoT project. Before writing or editing ANY code, config, or experiment script, first explain the full plan in plain language and wait for Creamy's explicit approval. Use this whenever a task would involve Write/Edit on code, changing config.yaml, changing a model/endpoint, or launching an experiment run.
---

# Plan before coding

Creamy's hard rule for this project. Violating it has cost real time and money
(a 40-minute experiment run was invalidated because a model was swapped without
first testing whether the new model was any good).

## The rule

**Never call Write / Edit / launch an experiment until the plan has been
explained AND Creamy has said go.**

## What to do instead, every time

1. **Investigate first.** Read the relevant code/data so the plan is grounded in
   what is actually there, not assumptions. Investigation (Read/Grep/Bash
   read-only) does NOT need approval — only changes do.
2. **Explain in plain English**, short and concrete:
   - What the problem actually is (with evidence — numbers, file:line)
   - What exactly will change (which files, which behaviour)
   - **Trade-offs and risks** — especially anything that could make results
     worse, invalidate an experiment, or cost money/time
   - Alternatives, with a clear recommendation
3. **Ask, then wait.** Do not start until there is an explicit go-ahead.

Creamy is not a native English speaker — keep explanations simple and short.
Use tables/bullets over long paragraphs.

## Extra rules learned the hard way

- **Smoke-test before committing to a long run.** If a change affects an
  experiment (new model, new endpoint, new prompt), test it on a handful of
  known-tricky cases FIRST and show the comparison. Never let a 40-minute run
  be the thing that discovers a regression.
- **Changing a model/endpoint is a quality risk, not just a "comparability
  note."** Say so loudly, and verify before running.
- **Flag when a "fix" might make results worse.** e.g. deterministic handlers
  can outscore an LLM; don't assume routing to a fancier agent is an upgrade.
- **Report failures honestly** — if a run crashed, scored badly, or a previous
  claim was wrong, say it plainly and early.

## Applies to

- Editing `main.py`, `router.py`, `config.yaml`, prompts, agents
- Changing FI routing, models, base URLs, API keys
- Launching Part A/B/C runs, re-scoring, LLM-judge runs
- Anything that spends money (cloud API) or GPU time

## Does NOT apply to

- Read-only investigation, grep/search, reading logs
- Generating a graph/table from data that already exists
- Answering questions
