"""Score the existing predict_url function on evaluation_dataset.csv.

Run from the repository root:

    python model_evaluation/evaluate.py

This does not modify model.py, app.py, or the frontend. It does not request
the URLs in the dataset.
"""

from __future__ import annotations

import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model import predict_url  # noqa: E402

HERE = Path(__file__).resolve().parent
DATASET = HERE / "evaluation_dataset.csv"
PREDICTIONS = HERE / "evaluation_predictions.csv"
METRICS = HERE / "evaluation_metrics.json"
MATRIX = HERE / "confusion_matrix.png"

LABELS = ("phishing", "legitimate")
KEYWORDS = ("login", "verify", "secure", "account", "update", "signin", "bank", "paypal", "wallet")
BRANDS = (
    "google",
    "whatsapp",
    "microsoft",
    "github",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "facebook",
    "instagram",
)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def structure(url: str) -> dict:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    ip = host.replace(".", "").isdigit() and host.count(".") == 3
    return {
        "scheme": parts.scheme,
        "host": host,
        "www": host.startswith("www."),
        "length": len(url),
        "path": parts.path not in ("", "/"),
        "query": bool(parts.query),
        "ip": ip,
        "hyphen": "-" in (host + parts.path),
        "keyword": any(word in url.lower() for word in KEYWORDS),
        "brand": any(word in url.lower() for word in BRANDS),
        "subdomain": (not ip) and host.count(".") >= 2 and not host.startswith("www."),
    }


def rates(rows: list[dict]) -> dict:
    matrix = Counter()
    for row in rows:
        matrix[(row["expected_label"], row["predicted_label"])] += 1
    tp = matrix[("phishing", "phishing")]
    fn = matrix[("phishing", "legitimate")]
    fp = matrix[("legitimate", "phishing")]
    tn = matrix[("legitimate", "legitimate")]
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    legit = tp_legit_base = fp + tn
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


def confidence_summary(rows: list[dict], key: str) -> dict:
    values = sorted(float(row[key]) for row in rows)
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


def group_error(rows: list[dict], predicate) -> dict:
    chosen = [row for row in rows if predicate(row)]
    if not chosen:
        return {"n": 0}
    wrong = [row for row in chosen if row["predicted_label"] != row["expected_label"]]
    return {
        "n": len(chosen),
        "errors": len(wrong),
        "error_rate": len(wrong) / len(chosen),
    }


def draw_matrix(counts: dict, path: Path) -> None:
    order = LABELS
    grid = [
        [counts[("phishing", "phishing")], counts[("phishing", "legitimate")]],
        [counts[("legitimate", "phishing")], counts[("legitimate", "legitimate")]],
    ]
    image = Image.new("RGB", (760, 460), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((24, 18), "URLBERT phiusiil head - primary evaluation", fill="black", font=font)
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


def main() -> None:
    with DATASET.open(encoding="utf-8", newline="") as handle:
        dataset = list(csv.DictReader(handle))
    primary = [row for row in dataset if row["split"] == "primary"]
    if len(primary) != 100:
        raise SystemExit(f"Expected 100 primary rows, found {len(primary)}")

    started = time.perf_counter()
    scored = []
    for row in primary:
        prediction = predict_url(row["url"])
        if prediction.get("error"):
            raise SystemExit(f"predict_url failed for {row['url']}: {prediction['error']}")
        scored.append(
            {
                **row,
                "predicted_label": prediction["label"],
                "confidence": prediction["confidence"],
                "prob_phishing": prediction["probabilities"]["phishing"],
                "prob_legitimate": prediction["probabilities"]["legitimate"],
                **{f"feat_{key}": value for key, value in structure(row["url"]).items()},
            }
        )
    elapsed = time.perf_counter() - started

    summary = rates(scored)
    summary["seconds_total"] = round(elapsed, 2)
    summary["seconds_per_url"] = round(elapsed / len(scored), 4)
    legitimate = [row for row in scored if row["expected_label"] == "legitimate"]
    phishing = [row for row in scored if row["expected_label"] == "phishing"]
    false_positives = [row for row in legitimate if row["predicted_label"] == "phishing"]
    false_negatives = [row for row in phishing if row["predicted_label"] == "legitimate"]
    summary["confidence"] = {
        "true_legitimate_correct": confidence_summary(
            [row for row in legitimate if row["predicted_label"] == "legitimate"], "confidence"
        ),
        "false_positives": confidence_summary(false_positives, "confidence"),
        "true_phishing_correct": confidence_summary(
            [row for row in phishing if row["predicted_label"] == "phishing"], "confidence"
        ),
        "false_negatives": confidence_summary(false_negatives, "confidence"),
    }
    summary["subgroups"] = {
        "legitimate_with_www": group_error(legitimate, lambda row: row["feat_www"] is True or row["feat_www"] == "True"),
        "legitimate_without_www": group_error(legitimate, lambda row: row["feat_www"] is False or row["feat_www"] == "False"),
        "legitimate_http": group_error(legitimate, lambda row: row["feat_scheme"] == "http"),
        "legitimate_https": group_error(legitimate, lambda row: row["feat_scheme"] == "https"),
        "legitimate_with_path": group_error(legitimate, lambda row: str(row["feat_path"]) == "True"),
        "legitimate_with_query": group_error(legitimate, lambda row: str(row["feat_query"]) == "True"),
        "legitimate_with_brand": group_error(legitimate, lambda row: str(row["feat_brand"]) == "True"),
        "legitimate_with_hyphen": group_error(legitimate, lambda row: str(row["feat_hyphen"]) == "True"),
        "legitimate_with_keyword": group_error(legitimate, lambda row: str(row["feat_keyword"]) == "True"),
        "phishing_http": group_error(phishing, lambda row: row["feat_scheme"] == "http"),
        "phishing_https": group_error(phishing, lambda row: row["feat_scheme"] == "https"),
        "phishing_with_path": group_error(phishing, lambda row: str(row["feat_path"]) == "True"),
        "phishing_with_query": group_error(phishing, lambda row: str(row["feat_query"]) == "True"),
        "phishing_with_hyphen": group_error(phishing, lambda row: str(row["feat_hyphen"]) == "True"),
        "phishing_with_keyword": group_error(phishing, lambda row: str(row["feat_keyword"]) == "True"),
        "phishing_subdomain": group_error(phishing, lambda row: str(row["feat_subdomain"]) == "True"),
        "phishing_ip": group_error(phishing, lambda row: str(row["feat_ip"]) == "True"),
    }
    lengths = sorted(int(row["feat_length"]) for row in scored)
    median_length = lengths[len(lengths) // 2]
    summary["subgroups"]["legitimate_length_at_or_above_median"] = group_error(
        legitimate, lambda row: int(row["feat_length"]) >= median_length
    )
    summary["subgroups"]["legitimate_length_below_median"] = group_error(
        legitimate, lambda row: int(row["feat_length"]) < median_length
    )
    summary["median_url_length"] = median_length
    summary["false_positive_urls"] = [row["url"] for row in false_positives]
    summary["false_negative_urls"] = [row["url"] for row in false_negatives]

    fieldnames = list(scored[0].keys())
    with PREDICTIONS.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(scored)
    METRICS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    matrix_counts = {
        ("phishing", "phishing"): summary["confusion_matrix"]["true_phishing_predicted_phishing"],
        ("phishing", "legitimate"): summary["confusion_matrix"]["true_phishing_predicted_legitimate"],
        ("legitimate", "phishing"): summary["confusion_matrix"]["true_legitimate_predicted_phishing"],
        ("legitimate", "legitimate"): summary["confusion_matrix"]["true_legitimate_predicted_legitimate"],
    }
    draw_matrix(matrix_counts, MATRIX)
    print(json.dumps({key: summary[key] for key in ("n", "accuracy", "precision_phishing", "recall_phishing", "f1_phishing", "false_positive_rate", "false_negative_rate", "confusion_matrix", "seconds_per_url")}, indent=2))


if __name__ == "__main__":
    main()
