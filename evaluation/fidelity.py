"""
evaluation/fidelity.py
─────────────────────────────────────────────────────────────────
All fidelity scoring methods in one file.
Each method is SEPARATE so trends can be analyzed independently.

Methods:
  cosine_score_response()   → TF-IDF cosine similarity (semantic)
  sequence_score_response() → difflib SequenceMatcher (syntax/structure)
  bleu_score_response()     → BLEU score (n-gram overlap)
  bert_score_response()     → BERTScore (deep semantic via BERT)

Unified entry:
  score_all(results, method="cosine"/"sequence"/"bleu"/"bert"/"all")

"all" runs every method and returns all scores per entry — use this
for the multi-metric graph in eval_compare.py

Reusable in any file:
  from fidelity import score_all
  results = score_all(results, method="all")
─────────────────────────────────────────────────────────────────
"""

import difflib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from normalization import normalize_pair

# ─── Helper ───────────────────────────────────────────────────────────────────

def _cuda_available() -> bool:
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False

def _empty_scores() -> dict:
    """Return zero scores for all metrics — used when input is empty."""
    return {
        "cosine_score":   0.0,
        "sequence_score": 0.0,
        "bleu_score":     0.0,
        "bert_f1":        0.0,
        "bert_precision": 0.0,
        "bert_recall":    0.0,
        "exact_match":    0,
    }

# ── optional libraries ────────────────────────────────────────────────────────
try:
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    import nltk
    nltk.download("punkt", quiet=True)
    BLEU_AVAILABLE = True
except ImportError:
    BLEU_AVAILABLE = False
    print("[fidelity] nltk not found — install with: pip install nltk")

try:
    from bert_score import score as bert_score_fn, BERTScorer
    BERT_AVAILABLE = True
    _bert_scorer = BERTScorer(
        lang                  = "en",
        rescale_with_baseline = False,
        device                = "cuda" if _cuda_available() else "cpu",
    )
except ImportError:
    BERT_AVAILABLE = False
    _bert_scorer   = None
    print("[fidelity] bert-score not found — install with: pip install bert-score")

# ─── Method 1: Cosine Similarity ─────────────────────────────────────────────

def cosine_score_response(predicted: str, ground_truth: str) -> dict:
    """
    TF-IDF cosine similarity — measures SEMANTIC meaning.
    Good for: checking if output has the right meaning
    Weakness: ignores word order and structure

    Returns: cosine_score (0-1), exact_match
    """
    if not predicted or not ground_truth:
        return {"cosine_score": 0.0, "exact_match": 0}

    predicted, ground_truth = normalize_pair(predicted, ground_truth)

    try:
        vectorizer   = TfidfVectorizer(stop_words=None)
        tfidf        = vectorizer.fit_transform([predicted, ground_truth])
        cosine_score = round(float(cosine_similarity(tfidf[0], tfidf[1])[0][0]), 4)
    except ValueError:
        cosine_score = 0.0
    except Exception:
        cosine_score = 0.0

    return {
        "cosine_score": cosine_score,
        "exact_match":  int(predicted.strip() == ground_truth.strip()),
    }

# ─── Method 2: Sequence Matcher ──────────────────────────────────────────────

def sequence_score_response(predicted: str, ground_truth: str) -> dict:
    """
    difflib SequenceMatcher — measures SYNTAX/STRUCTURE similarity.
    Good for: checking if output has the right format/layout
    Weakness: sensitive to small character differences

    Returns: sequence_score (0-1), exact_match
    """
    if not predicted or not ground_truth:
        return {"sequence_score": 0.0, "exact_match": 0}

    predicted, ground_truth = normalize_pair(predicted, ground_truth)

    sequence_score = round(
        difflib.SequenceMatcher(None, predicted, ground_truth).ratio(), 4
    )

    return {
        "sequence_score": sequence_score,
        "exact_match":    int(predicted.strip() == ground_truth.strip()),
    }

# ─── Method 3: BLEU Score ────────────────────────────────────────────────────

def bleu_score_response(predicted: str, ground_truth: str) -> dict:
    """
    BLEU score — measures N-GRAM OVERLAP.
    Good for: checking if output uses the same words/phrases
    Weakness: penalizes short outputs, ignores paraphrasing

    Returns: bleu_score (0-1), exact_match
    """
    if not BLEU_AVAILABLE:
        print("[fidelity] BLEU not available — install nltk")
        return {"bleu_score": 0.0, "exact_match": 0}

    if not predicted or not ground_truth:
        return {"bleu_score": 0.0, "exact_match": 0}

    predicted, ground_truth = normalize_pair(predicted, ground_truth)

    try:
        # tokenize into words
        ref  = [ground_truth.split()]   # reference needs to be list of lists
        hyp  = predicted.split()

        # smoothing handles cases where n-gram matches are 0
        smooth     = SmoothingFunction().method1
        bleu_score = round(sentence_bleu(ref, hyp, smoothing_function=smooth), 4)
    except Exception as e:
        print(f"[fidelity] BLEU failed: {e}")
        bleu_score = 0.0

    return {
        "bleu_score":  bleu_score,
        "exact_match": int(predicted.strip() == ground_truth.strip()),
    }

# ─── Method 4: BERTScore ─────────────────────────────────────────────────────

def bert_score_response(predicted: str, ground_truth: str) -> dict:
    """
    BERTScore — deep SEMANTIC similarity via BERT embeddings.
    Good for: catching paraphrases and meaning even with different words
    Weakness: slow, requires GPU for reasonable speed

    Returns: bert_precision, bert_recall, bert_f1 (0-1), exact_match
    """
    if not BERT_AVAILABLE:
        print("[fidelity] BERTScore not available — install bert-score")
        return {"bert_precision": 0.0, "bert_recall": 0.0, "bert_f1": 0.0, "exact_match": 0}

    if not predicted or not ground_truth:
        return {"bert_precision": 0.0, "bert_recall": 0.0, "bert_f1": 0.0, "exact_match": 0}

    predicted, ground_truth = normalize_pair(predicted, ground_truth)

    try:
        # use pre-loaded scorer — no model reload per call
        P, R, F1 = _bert_scorer.score([predicted], [ground_truth])
        return {
            "bert_precision": round(float(P[0]),  4),
            "bert_recall":    round(float(R[0]),  4),
            "bert_f1":        round(float(F1[0]), 4),
            "exact_match":    int(predicted.strip() == ground_truth.strip()),
        }
    except Exception as e:
        print(f"[fidelity] BERTScore failed: {e}")
        return {"bert_precision": 0.0, "bert_recall": 0.0, "bert_f1": 0.0, "exact_match": 0}

# ─── Combined: All Methods ────────────────────────────────────────────────────

def all_score_response(predicted: str, ground_truth: str) -> dict:
    """
    Run ALL methods separately — no combining.
    Each metric is independent so trends can be analyzed clearly.

    cosine_score   → semantic meaning
    sequence_score → syntax/structure
    bleu_score     → n-gram overlap
    bert_f1        → deep semantic via BERT
    exact_match    → 1 if identical
    """
    if not predicted or not ground_truth:
        return _empty_scores()

    scores = {}
    scores.update(cosine_score_response(predicted,   ground_truth))
    scores.update(sequence_score_response(predicted, ground_truth))
    scores.update(bleu_score_response(predicted,     ground_truth))
    scores.update(bert_score_response(predicted,     ground_truth))

    return scores

# ─── Batch Scorers ────────────────────────────────────────────────────────────

def cosine_score_all(results: list, output_key: str = "ondevice_output") -> list:
    return _batch_score(results, output_key, cosine_score_response)

def sequence_score_all(results: list, output_key: str = "ondevice_output") -> list:
    return _batch_score(results, output_key, sequence_score_response)

def bleu_score_all(results: list, output_key: str = "ondevice_output") -> list:
    return _batch_score(results, output_key, bleu_score_response)

def bert_score_all(results: list, output_key: str = "ondevice_output") -> list:
    return _batch_score(results, output_key, bert_score_response)

def all_score_all(results: list, output_key: str = "ondevice_output") -> list:
    return _batch_score(results, output_key, all_score_response)

def _batch_score(results: list, output_key: str, fn) -> list:
    """Internal batch scorer — applies fn to every result."""
    scored = []
    for r in results:
        entry  = dict(r)
        scores = fn(
            r.get(output_key,     ""),
            r.get("ground_truth", ""),
        )
        entry.update(scores)
        scored.append(entry)
    return scored

# ─── Unified Entry Point ──────────────────────────────────────────────────────

def score_all(results: list, method: str = "all", output_key: str = "ondevice_output") -> list:
    """
    Unified batch scorer — pick method here.

    Args:
        results    : list of result dicts
        method     : "cosine" / "sequence" / "bleu" / "bert" / "all" (default)
        output_key : "ondevice_output" or "cowrie_output"

    Usage:
        from fidelity import score_all
        results = score_all(results, method="all")       # all metrics
        results = score_all(results, method="cosine")    # cosine only
        results = score_all(results, method="bleu")      # BLEU only
    """
    methods = {
        "cosine":   cosine_score_all,
        "sequence": sequence_score_all,
        "bleu":     bleu_score_all,
        "bert":     bert_score_all,
        "all":      all_score_all,
    }

    if method not in methods:
        print(f"[fidelity] unknown method '{method}' — using 'all'")
        method = "all"

    return methods[method](results, output_key)