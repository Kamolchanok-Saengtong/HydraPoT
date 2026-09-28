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
CACHE = os.path.join(_HERE, "out", "embeddings.npz")
MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


def _key(model: str) -> str:
    return hashlib.sha1(model.encode()).hexdigest()[:8]


def embed(commands, model: str = MODEL, refresh: bool = False) -> dict:
    """{command_text: vector}. Cached on disk, keyed by the encoder used."""
    commands = sorted(set(commands))
    if os.path.exists(CACHE) and not refresh:
        z = np.load(CACHE, allow_pickle=True)
        if str(z["model_key"]) == _key(model) and len(z["texts"]) == len(commands):
            return dict(zip(z["texts"].tolist(), z["vectors"]))

    from sentence_transformers import SentenceTransformer
    enc = SentenceTransformer(model)
    vecs = enc.encode(commands, batch_size=64, show_progress_bar=False,
                      normalize_embeddings=True)
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    np.savez_compressed(CACHE, texts=np.array(commands, dtype=object),
                        vectors=np.asarray(vecs, dtype=np.float32),
                        model_key=_key(model))
    print(f"[embed] {len(commands)} commands -> {np.shape(vecs)} -> {CACHE}")
    return dict(zip(commands, vecs))


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(_HERE))
    from honeyrouter.sessions import load_sessions
    cmds = [c["cmd"] for v in load_sessions().values() for c in v]
    t = embed(cmds)
    print(f"[embed] distinct={len(t)}  dim={next(iter(t.values())).shape[0]}")
