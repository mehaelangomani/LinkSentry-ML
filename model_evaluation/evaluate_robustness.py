"""Score PhiUSIIL and the ealvaradob head on frozen robustness splits.

Thresholds are chosen on robustness_validation.csv only, then applied once
to robustness_test.csv. Synthetic rows are never mixed into those metrics.

    python model_evaluation/evaluate_robustness.py
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

HERE = Path(__file__).resolve().parent
REPO = "CrabInHoney/urlbert-tiny-v6"
REVISION = "020744435b3be870dabb2bba0b41237bea69b84b"
HEADS = {
    "phiusiil": "heads/phiusiil_phishing_url",
    "ealvaradob": "heads/ealvaradob_phishing_dataset",
}
EXPECTED_MAPS = {
    "phiusiil": {0: "phishing", 1: "legitimate"},
    "ealvaradob": {0: "legitimate", 1: "phishing"},
}
CANDIDATE_THRESHOLDS = [round(0.50 + 0.05 * step, 2) for step in range(10)]
PRIOR_ERRORS = [
    "https://web.whatsapp.com",
    "https://github.com",
    "https://login.microsoftonline.com",
    "http://neverssl.com",
    "https://news.ycombinator.com",
    "https://cdn.jsdelivr.net/npm/react/package.json",
    "https://old.reddit.com",
    "https://outlook.live.com",
    "https://store.workshopcommunitybrowse.com/sharedfiles/filesdetails/id=3832495514/",
    "https://roblox.com.bz/games/82205993156224/Walk-10000-Stairs-for-Neko-Girl?privateServerLinkCode=01763772834170954578562896236934",
    "http://thrshopee155.blogspot.com/",
    "https://www.roblox.com.et/users/2717531752/profile",
]
TOKEN_REFERENCES = [
    "https://www.roblox.com/",
    "https://www.roblox.com/games",
    "https://roblox.com/",
]


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def label_map(model) -> dict[int, str]:
    return {int(index): str(name) for index, name in model.config.id2label.items()}


def probabilities(model, tokenizer, url: str) -> dict:
    max_length = int(model.config.max_length)
    encoded = tokenizer(url, return_tensors="pt", truncation=True, max_length=max_length)
    token_ids = encoded["input_ids"][0].tolist()
    with torch.inference_mode():
        logits = model(**encoded).logits
    probs = torch.softmax(logits, dim=-1)[0]
    mapping = label_map(model)
    by_name = {mapping[index]: float(probs[index].item()) for index in mapping}
    if set(by_name) != {"phishing", "legitimate"}:
        raise SystemExit(f"Unexpected labels {mapping}")
    return {
        "p_phishing": by_name["phishing"],
        "p_legitimate": by_name["legitimate"],
        "n_tokens": len(token_ids),
        "tokens": tokenizer.convert_ids_to_tokens(token_ids),
        "truncated": len(token_ids) >= max_length,
        "decoded": tokenizer.decode(token_ids, skip_special_tokens=True),
    }


def apply_threshold(rows: list[dict], threshold: float) -> list[dict]:
    scored = []
    for row in rows:
        predicted = "phishing" if row["p_phishing"] >= threshold else "legitimate"
        scored.append({**row, "predicted_label": predicted, "threshold": threshold})
    return scored


def metrics(rows: list[dict]) -> dict:
    matrix = Counter((row["expected_label"], row["predicted_label"]) for row in rows)
    tp = matrix[("phishing", "phishing")]
    fn = matrix[("phishing", "legitimate")]
    fp = matrix[("legitimate", "phishing")]
    tn = matrix[("legitimate", "legitimate")]
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    legit = fp + tn
    phish = fn + tp
    return {
        "n": total,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision_phishing": precision,
        "recall_phishing": recall,
        "f1_phishing": f1,
        "false_positive_rate": fp / legit if legit else 0.0,
        "false_negative_rate": fn / phish if phish else 0.0,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
    }


def confidence_summary(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    ordered = sorted(values)

    def quantile(q: float) -> float:
        index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
        return ordered[index]

    return {
        "n": len(ordered),
        "min": ordered[0],
        "median": quantile(0.5),
        "mean": sum(ordered) / len(ordered),
        "max": ordered[-1],
        "below_0_70": sum(value < 0.70 for value in ordered),
        "at_least_0_90": sum(value >= 0.90 for value in ordered),
        "at_least_0_98": sum(value >= 0.98 for value in ordered),
    }


def choose_threshold(rows: list[dict]) -> dict:
    """Validation-only rule, fixed before the test split is scored.

    Predict phishing when P(phishing) >= t.
    Keep a candidate only when its recall is at least 0.85 and no more than
    0.05 below the recall at 0.50. Among those, take the lowest false-positive
    rate, then the higher F1, then the lower threshold.
    """
    base = metrics(apply_threshold(rows, 0.50))
    eligible = []
    table = []
    for threshold in CANDIDATE_THRESHOLDS:
        stats = metrics(apply_threshold(rows, threshold))
        table.append({"threshold": threshold, **stats})
        recall_ok = stats["recall_phishing"] >= 0.85 and stats["recall_phishing"] >= base["recall_phishing"] - 0.05 - 1e-12
        if recall_ok:
            eligible.append((stats["false_positive_rate"], -stats["f1_phishing"], threshold, stats))
    if not eligible:
        return {"threshold": 0.50, "reason": "no candidate kept recall within 5 points of the 0.50 operating point and at least 0.85", "validation_curve": table, "validation_at_threshold": base}
    eligible.sort()
    _fpr, _f1, threshold, stats = eligible[0]
    return {
        "threshold": threshold,
        "reason": "lowest validation false-positive rate subject to the recall constraint",
        "validation_curve": table,
        "validation_at_threshold": stats,
    }


def category_table(rows: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        key = f"{row['expected_label']}:{row['category']}"
        grouped.setdefault(key, []).append(row)
    return {key: metrics(grouped[key]) for key in sorted(grouped)}


def compact_errors(rows: list[dict]) -> list[dict]:
    errors = []
    for row in rows:
        if row["predicted_label"] == row["expected_label"]:
            continue
        errors.append(
            {
                "url": row["url"],
                "expected_label": row["expected_label"],
                "predicted_label": row["predicted_label"],
                "category": row["category"],
                "p_phishing": round(row["p_phishing"], 4),
                "p_legitimate": round(row["p_legitimate"], 4),
            }
        )
    return errors


def token_record(tokenizer, url: str) -> dict:
    encoded = tokenizer(url, truncation=True, max_length=512)
    tokens = tokenizer.convert_ids_to_tokens(encoded["input_ids"])
    decoded = tokenizer.decode(encoded["input_ids"], skip_special_tokens=True)
    return {
        "url": url,
        "tokens": tokens,
        "decoded_without_special_tokens": decoded,
        "decoded_matches_url": decoded == url,
        "n_tokens": len(tokens),
    }


def main() -> None:
    validation = read_csv(HERE / "robustness_validation.csv")
    test = read_csv(HERE / "robustness_test.csv")
    synthetic = read_csv(HERE / "robustness_synthetic.csv")
    original = {row["url"] for row in read_csv(HERE / "evaluation_dataset.csv")}
    for name, rows in ("validation", validation), ("test", test), ("synthetic", synthetic):
        overlap = original & {row["url"] for row in rows}
        if overlap:
            raise SystemExit(f"{name} overlaps the original evaluation set: {sorted(overlap)[:5]}")
    if {row["url"] for row in validation} & {row["url"] for row in test}:
        raise SystemExit("validation and test share URLs")

    tokenizer = AutoTokenizer.from_pretrained(REPO, revision=REVISION)
    models = {}
    maps = {}
    for name, subfolder in HEADS.items():
        model = AutoModelForSequenceClassification.from_pretrained(
            REPO, subfolder=subfolder, revision=REVISION, trust_remote_code=True
        )
        model.eval()
        found = label_map(model)
        if found != EXPECTED_MAPS[name]:
            raise SystemExit(f"{name} label map {found} does not match {EXPECTED_MAPS[name]}")
        models[name] = model
        maps[name] = found

    def score_split(rows: list[dict], model_name: str) -> list[dict]:
        scored = []
        model = models[model_name]
        for row in rows:
            probs = probabilities(model, tokenizer, row["url"])
            scored.append(
                {
                    **row,
                    "p_phishing": probs["p_phishing"],
                    "p_legitimate": probs["p_legitimate"],
                    "n_tokens": probs["n_tokens"],
                    "truncated": probs["truncated"],
                }
            )
        return scored

    report = {
        "label_maps": maps,
        "threshold_rule": {
            "candidates": CANDIDATE_THRESHOLDS,
            "predict_phishing_when": "P(phishing) >= threshold",
            "constraint": "validation recall >= 0.85 and within 0.05 of the 0.50 recall",
            "objective": "lowest validation false-positive rate, then higher F1, then lower threshold",
        },
        "models": {},
        "prior_error_tokens": [token_record(tokenizer, url) for url in PRIOR_ERRORS],
        "roblox_reference_tokens": [token_record(tokenizer, url) for url in TOKEN_REFERENCES],
    }
    reference_scores = {}
    for model_name in HEADS:
        reference_scores[model_name] = []
        for url in TOKEN_REFERENCES:
            probs = probabilities(models[model_name], tokenizer, url)
            reference_scores[model_name].append(
                {
                    "url": url,
                    "role": "analysis_only_not_in_verified_metrics",
                    "p_phishing": round(probs["p_phishing"], 4),
                    "p_legitimate": round(probs["p_legitimate"], 4),
                    "tokens": probs["tokens"],
                }
            )
    report["roblox_reference_scores"] = reference_scores

    summaries = {}
    for model_name in HEADS:
        validation_scores = score_split(validation, model_name)
        choice = choose_threshold(validation_scores)
        threshold = choice["threshold"]
        test_scores = score_split(test, model_name)
        default_rows = apply_threshold(test_scores, 0.50)
        tuned_rows = apply_threshold(test_scores, threshold)
        synthetic_scores = score_split(synthetic, model_name)
        synthetic_view = []
        for row in synthetic_scores:
            synthetic_view.append(
                {
                    "url": row["url"],
                    "expected_label": row["expected_label"],
                    "verification_status": row["verification_status"],
                    "p_phishing": round(row["p_phishing"], 4),
                    "p_legitimate": round(row["p_legitimate"], 4),
                    "predicted_at_0_50": "phishing" if row["p_phishing"] >= 0.50 else "legitimate",
                }
            )
        correct = [row for row in default_rows if row["predicted_label"] == row["expected_label"]]
        wrong = [row for row in default_rows if row["predicted_label"] != row["expected_label"]]
        summaries[model_name] = {
            "validation_threshold": choice,
            "test_at_0_50": metrics(default_rows),
            "test_at_validation_threshold": metrics(tuned_rows),
            "test_errors_at_0_50": compact_errors(default_rows),
            "test_errors_at_validation_threshold": compact_errors(tuned_rows),
            "test_categories_at_0_50": category_table(default_rows),
            "confidence_at_0_50": {
                "correct_p_predicted_class": confidence_summary(
                    [row["p_phishing"] if row["predicted_label"] == "phishing" else row["p_legitimate"] for row in correct]
                ),
                "false_positive_p_phishing": confidence_summary(
                    [row["p_phishing"] for row in wrong if row["expected_label"] == "legitimate"]
                ),
                "false_negative_p_legitimate": confidence_summary(
                    [row["p_legitimate"] for row in wrong if row["expected_label"] == "phishing"]
                ),
            },
            "synthetic_not_in_verified_metrics": synthetic_view,
            "test_any_truncated": any(row["truncated"] for row in test_scores),
            "test_max_tokens": max(int(row["n_tokens"]) for row in test_scores),
        }
    report["models"] = summaries
    (HERE / "robustness_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    printable = {}
    for name, summary in summaries.items():
        printable[name] = {
            "threshold": summary["validation_threshold"]["threshold"],
            "reason": summary["validation_threshold"]["reason"],
            "test_at_0_50": summary["test_at_0_50"],
            "test_at_validation_threshold": summary["test_at_validation_threshold"],
            "false_positives": [row["url"] for row in summary["test_errors_at_0_50"] if row["expected_label"] == "legitimate"],
            "false_negatives": [row["url"] for row in summary["test_errors_at_0_50"] if row["expected_label"] == "phishing"],
        }
    print(json.dumps(printable, indent=2))


if __name__ == "__main__":
    main()
