"""
honeyrouter/names.py -- the four Phase-1 identities and the names people use for them.

No imports on purpose: the training CLI and the predictor both read this, and
neither should have to load torch to learn a label.

                 identity (the vector)               neural networks
    paper-128        learned, 128 numbers                trained
    bench-fixed      benchmark score, 1 number, frozen   none (nothing trained)
    bench-fixed+net  benchmark score, 1 number, frozen   trained
    bench-learn+net  benchmark score, 1 number, starts   trained, and the score
                     at the benchmark, then LEARNED      moves with them

The flag values (--identity irt|vector|vector_irt|vector_learn) are what folders,
config.json and old results already use, so they stay; the labels are accepted
anywhere a flag value is.
"""

IDENTITY_LABELS = {
    "irt": "paper-128",
    "vector": "bench-fixed",
    "vector_irt": "bench-fixed+net",
    "vector_learn": "bench-learn+net",
}

# Identities with no learned posterior: the vector is one point, not a distribution
POINT_IDENTITIES = ("vector_irt", "vector_learn")

_BY_LABEL = {label: key for key, label in IDENTITY_LABELS.items()}


def canonical_identity(name: str) -> str:
    """A label or a flag value -> the flag value the code uses."""
    return _BY_LABEL.get(name, name)
