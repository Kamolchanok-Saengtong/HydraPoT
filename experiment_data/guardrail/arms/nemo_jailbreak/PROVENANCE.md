# Vendored from NVIDIA NeMo Guardrails

Only the jailbreak-detection rail is kept; docs, examples, tests, the other 35
rails and the .git history are not needed to run this as a detector arm.

    source : https://github.com/NVIDIA-NeMo/Guardrails
    path   : nemoguardrails/library/jailbreak_detection/
    commit : f4d8348d68b868c55a1861222a243aa5ebab27b0
    cloned : 2026-10-15
    licence: Apache-2.0 (LICENSE-Apache-2.0.txt, LICENSE.md)

heuristics/checks.py imports only os, torch and transformers, so it runs
standalone. model_based/ expects a separately served classifier (see its
Dockerfile) and is kept for reference, not wired in.
