"""Score the ealvaradob_phishing_dataset head on the frozen evaluation CSV.

Run from the repository root:

    python model_evaluation/evaluate_ealvaradob.py

This does not call predict_url(), and it does not modify model.py, app.py,
or the frontend. Class 0 on this head is legitimate, which is the opposite
of the PhiUSIIL head, so probabilities are read through id2label.
"""

from __future__ import annotations

import csv
import json
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import torch
from PIL import Image, ImageDraw, ImageFont
from transformers import AutoModelForSequenceClassification, AutoTokenizer

HERE = Path(__file__).resolve().parent
DATASET = HERE / "evaluation_dataset.csv"
PREDICTIONS = HERE / "ealvaradob_predictions.csv"
METRICS = HERE / "ealvaradob_metrics.json"
MATRIX = HERE / "ealvaradob_confusion_matrix.png"

REPO = "CrabInHoney/urlbert-tiny-v6"
REVISION = "020744435b3be870dabb2bba0b41237bea69b84b"
HEAD = "heads/ealvaradob_phishing_dataset"
FOCUS = (
    "https://github.com",
    "https://web.whatsapp.com",
    "https://accounts.google.com",
    "https://login.microsoftonline.com",
)


def structure(url: str) -> dict:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return {
        "scheme": parts.scheme,
        "host": host,
        "www": host.startswith("www."),
        "path": parts.path not in ("", "/"),
        "query": bool(parts.query),
    }


def rates(rows: list[dict]) -> dict:
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
        "confusion_matrix": {
            "true_phishing_predicted_phishing": tp,
            "true_phishing_predicted_legitimate": fn,
            "true_legitimate_predicted_phishing": fp,
            "true_legitimate_predicted_legitimate": tn,
        },
    }


def confidence_summary(rows: list[dict]) -> dict:
    values = sorted(float(row["confidence"]) for row in rows)
    if not values:
        return {"n": 0}

    def quantile(q: float) -> float:
        index = min(len(values) - 1, max(0, round(q * (len(values) - 1))))
        return values[index]

    return {
        "n": len(values),
        "min": values[0],
        "median": quantile(0.5),
        "mean": sum(values) / len(values),
        "max": values[-1],
        "at_least_90": sum(value >= 90 for value in values),
        "at_least_98": sum(value >= 98 for value in values),
    }


def working_set_bytes() -> int | None:
    try:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
        if not ok:
            return None
        return int(counters.WorkingSetSize)
    except Exception:
        return None


def draw_matrix(counts: dict, path: Path) -> None:
    grid = [
        [counts[("phishing", "phishing")], counts[("phishing", "legitimate")]],
        [counts[("legitimate", "phishing")], counts[("legitimate", "legitimate")]],
    ]
    image = Image.new("RGB", (760, 460), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((24, 18), "ealvaradob head - same 100 URLs", fill="black", font=font)
    draw.text((24, 40), "Rows are expected labels. Columns are predicted labels.", fill="black", font=font)
    left, top, size = 180, 90, 220
    peak = max(cell for row in grid for cell in row) or 1
    for row_index, row in enumerate(grid):
        for col_index, value in enumerate(row):
            shade = int(255 - (value / peak) * 180)
            color = (shade, shade, 255) if row_index == col_index else (255, shade, shade)
            x = left + col_index * size
            y = top + row_index * size
            draw.rectangle((x, y, x + size - 8, y + size - 8), fill=color, outline="black")
            draw.text((x + 80, y + 90), str(value), fill="black", font=font)
    draw.text((left + 70, 68), "predicted phishing", fill="black", font=font)
    draw.text((left + size + 60, 68), "predicted legitimate", fill="black", font=font)
    draw.text((20, top + 90), "true phishing", fill="black", font=font)
    draw.text((20, top + size + 90), "true legitimate", fill="black", font=font)
    image.save(path)


def predict_one(model, tokenizer, url: str) -> dict:
    max_length = int(model.config.max_length)
    inputs = tokenizer(url, return_tensors="pt", truncation=True, max_length=max_length)
    token_ids = inputs["input_ids"][0].tolist()
    with torch.inference_mode():
        logits = model(**inputs).logits
    probabilities = torch.softmax(logits, dim=-1)[0]
    by_name = {}
    for index, name in model.config.id2label.items():
        by_name[str(name)] = round(probabilities[int(index)].item() * 100, 2)
    predicted_index = int(probabilities.argmax().item())
    predicted = str(model.config.id2label[predicted_index])
    return {
        "predicted_label": predicted,
        "confidence": by_name[predicted],
        "prob_phishing": by_name["phishing"],
        "prob_legitimate": by_name["legitimate"],
        "n_tokens": len(token_ids),
        "truncated": len(token_ids) >= max_length,
    }


def main() -> None:
    started_load = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(REPO, revision=REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(
        REPO,
        subfolder=HEAD,
        revision=REVISION,
        trust_remote_code=True,
    )
    model.eval()
    load_seconds = time.perf_counter() - started_load

    labels = {int(index): str(name) for index, name in model.config.id2label.items()}
    if labels.get(0) != "legitimate" or labels.get(1) != "phishing":
        raise SystemExit(f"Unexpected label map: {labels}")

    head_params = sum(parameter.numel() for parameter in model.head.parameters())
    encoder_params = sum(parameter.numel() for parameter in model.encoder.parameters())
    memory_after_load = working_set_bytes()

    with DATASET.open(encoding="utf-8", newline="") as handle:
        dataset = list(csv.DictReader(handle))
    primary = [row for row in dataset if row["split"] == "primary"]
    if len(primary) != 100:
        raise SystemExit(f"Expected 100 primary rows, found {len(primary)}")

    started = time.perf_counter()
    scored = []
    for row in primary:
        prediction = predict_one(model, tokenizer, row["url"])
        if prediction["predicted_label"] not in {"phishing", "legitimate"}:
            raise SystemExit(f"Unexpected prediction {prediction} for {row['url']}")
        scored.append({**row, **prediction, **{f"feat_{key}": value for key, value in structure(row["url"]).items()}})
    elapsed = time.perf_counter() - started

    summary = rates(scored)
    legitimate = [row for row in scored if row["expected_label"] == "legitimate"]
    phishing = [row for row in scored if row["expected_label"] == "phishing"]
    false_positives = [row for row in legitimate if row["predicted_label"] == "phishing"]
    false_negatives = [row for row in phishing if row["predicted_label"] == "legitimate"]
    summary.update(
        {
            "repository": REPO,
            "revision": REVISION,
            "head": HEAD,
            "id2label": labels,
            "max_length": int(model.config.max_length),
            "tokenizer_do_lower_case": bool(getattr(tokenizer, "do_lower_case", False)),
            "encoder_params": encoder_params,
            "head_params": head_params,
            "load_seconds": round(load_seconds, 2),
            "working_set_mb_after_load": None if memory_after_load is None else round(memory_after_load / (1024 * 1024), 1),
            "seconds_total": round(elapsed, 2),
            "seconds_per_url": round(elapsed / len(scored), 4),
            "max_tokens_seen": max(int(row["n_tokens"]) for row in scored),
            "any_truncated": any(str(row["truncated"]) == "True" or row["truncated"] is True for row in scored),
            "confidence": {
                "true_legitimate_correct": confidence_summary(
                    [row for row in legitimate if row["predicted_label"] == "legitimate"]
                ),
                "false_positives": confidence_summary(false_positives),
                "true_phishing_correct": confidence_summary(
                    [row for row in phishing if row["predicted_label"] == "phishing"]
                ),
                "false_negatives": confidence_summary(false_negatives),
            },
            "false_positive_urls": [
                {
                    "url": row["url"],
                    "confidence": row["confidence"],
                    "prob_phishing": row["prob_phishing"],
                    "prob_legitimate": row["prob_legitimate"],
                }
                for row in false_positives
            ],
            "false_negative_urls": [
                {
                    "url": row["url"],
                    "confidence": row["confidence"],
                    "prob_phishing": row["prob_phishing"],
                    "prob_legitimate": row["prob_legitimate"],
                }
                for row in false_negatives
            ],
            "focus": [
                {
                    "url": row["url"],
                    "expected_label": row["expected_label"],
                    "predicted_label": row["predicted_label"],
                    "confidence": row["confidence"],
                    "prob_phishing": row["prob_phishing"],
                    "prob_legitimate": row["prob_legitimate"],
                }
                for row in scored
                if row["url"] in FOCUS
            ],
        }
    )
    path_rows = [row for row in legitimate if row["feat_path"] is True or row["feat_path"] == "True"]
    query_rows = [row for row in legitimate if row["feat_query"] is True or row["feat_query"] == "True"]
    summary["legitimate_with_path_errors"] = sum(row["predicted_label"] != "legitimate" for row in path_rows)
    summary["legitimate_with_path_n"] = len(path_rows)
    summary["legitimate_with_query_errors"] = sum(row["predicted_label"] != "legitimate" for row in query_rows)
    summary["legitimate_with_query_n"] = len(query_rows)

    with PREDICTIONS.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scored[0].keys()))
        writer.writeheader()
        writer.writerows(scored)
    METRICS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    draw_matrix(
        {
            ("phishing", "phishing"): summary["confusion_matrix"]["true_phishing_predicted_phishing"],
            ("phishing", "legitimate"): summary["confusion_matrix"]["true_phishing_predicted_legitimate"],
            ("legitimate", "phishing"): summary["confusion_matrix"]["true_legitimate_predicted_phishing"],
            ("legitimate", "legitimate"): summary["confusion_matrix"]["true_legitimate_predicted_legitimate"],
        },
        MATRIX,
    )
    printable = {
        key: summary[key]
        for key in (
            "accuracy",
            "precision_phishing",
            "recall_phishing",
            "f1_phishing",
            "false_positive_rate",
            "false_negative_rate",
            "confusion_matrix",
            "seconds_per_url",
            "load_seconds",
            "head_params",
            "encoder_params",
            "working_set_mb_after_load",
            "max_tokens_seen",
            "any_truncated",
            "focus",
            "legitimate_with_path_errors",
            "legitimate_with_path_n",
            "legitimate_with_query_errors",
            "legitimate_with_query_n",
        )
    }
    print(json.dumps(printable, indent=2))


if __name__ == "__main__":
    main()
