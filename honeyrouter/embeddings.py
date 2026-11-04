"""
honeyrouter/embeddings.py — prompt embeddings. Stage 0 of the LLM Bandit.

The paper's context is a pretrained embedding e_n of the query; ours is the
attacker's command. The encoder is FROZEN -- nothing in any later stage trains
it, which is what lets the identity vectors mean "ability relative to a fixed
view of the input" rather than drifting with the encoder.

Computed once for the distinct commands in the Part C replay and cached, since
Stage 1, Stage 2 and Stage 3 all read the same vectors.

MODEL: sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 (384-dim),
already in the local HF cache. Nothing depends on that particular encoder --
change MODEL and delete the cache to swap it.

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743
"""
import hashlib
import os

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
# Deliberately NOT redirected by HONEYROUTER_OUT, unlike predictor.py,
# routing_policy.py and reinforcement.py. These embeddings are a pure function
# of the commands and the model below -- no hyperparameter changes them -- so
# every config shares one cache instead of re-embedding 2179 commands per run
# for an identical result. Nothing a config run writes here can affect a
# trained model; the model artifacts are the ones that get their own folder.
CACHE = os.path.join(_HERE, "out", "embeddings.npz")
MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def _key(model: str) -> str:
    return hashlib.sha1(model.encode()).hexdigest()[:8]


def embed(commands, model: str = MODEL, refresh: bool = False) -> dict:
    """{command_text: vector}. Cached on disk, keyed by the encoder used.

    The cache is matched PER COMMAND TEXT and only ever grows. It used to be
    matched on len(texts) and rewritten whole, which quietly corrupted the
    live router: irt_router_live.pick() calls embed([cmd]) one command at a
    time, so a 1137-entry cache was overwritten with a single entry, and the
    next single-command call saw 1 == 1, took the hit, and returned the
    PREVIOUS command's vector. Routing then ran on the wrong embedding.
    """
    commands = sorted(set(commands))
    have, vecs_by_text = {}, {}
    if os.path.exists(CACHE) and not refresh:
        z = np.load(CACHE, allow_pickle=True)
        if str(z["model_key"]) == _key(model):
            vecs_by_text = dict(zip(z["texts"].tolist(), z["vectors"]))
            have = {c: vecs_by_text[c] for c in commands if c in vecs_by_text}
    missing = [c for c in commands if c not in have]
    if not missing:
        return have

    from sentence_transformers import SentenceTransformer
    enc = SentenceTransformer(model)
    new = enc.encode(missing, batch_size=64, show_progress_bar=False,
                     normalize_embeddings=True)
    have.update(zip(missing, new))
    vecs_by_text.update(zip(missing, new))

    # Union of old and new, written atomically: the live router and a training
    # run can both be embedding at once, and a half-written npz would be read
    # back as a corrupt cache by whichever got there second.
    texts = sorted(vecs_by_text)
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    tmp = f"{CACHE}.{os.getpid()}.tmp.npz"     # savez appends .npz otherwise
    np.savez_compressed(tmp, texts=np.array(texts, dtype=object),
                        vectors=np.asarray([vecs_by_text[t] for t in texts],
                                           dtype=np.float32),
                        model_key=_key(model))
    os.replace(tmp, CACHE)
    print(f"[embed] +{len(missing)} new, {len(texts)} cached -> {CACHE}")
    return have


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(_HERE))
    from honeyrouter.sessions import load_sessions
    cmds = [c["cmd"] for v in load_sessions().values() for c in v]
    t = embed(cmds)
    print(f"[embed] distinct={len(t)}  dim={next(iter(t.values())).shape[0]}")
