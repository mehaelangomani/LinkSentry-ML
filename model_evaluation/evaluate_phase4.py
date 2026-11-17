"""Score three local phishing/malicious-URL models on the frozen evaluation files.

Selection uses robustness_validation.csv only. The held-out robustness test,
the original 100-URL set, and the synthetic probes are scored after that
choice and are not inputs to it.

    python model_evaluation/evaluate_phase4.py
"""

from __future__ import annotations

import csv
import json
import time
import traceback
from collections import Counter
from pathlib import Path

import torch
from huggingface_hub import hf_hub_download
from PIL import Image, ImageDraw, ImageFont
from safetensors.torch import load_file
from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

HERE = Path(__file__).resolve().parent
CANDIDATE_THRESHOLDS = [round(0.50 + 0.05 * step, 2) for step in range(10)]
FOCUS_URLS = [
    "https://web.whatsapp.com",
    "https://github.com",
    "https://login.microsoftonline.com",
    "https://signin.aws.amazon.com/",
    "https://roblox.com.bz/games/82205993156224/Walk-10000-Stairs-for-Neko-Girl?privateServerLinkCode=01763772834170954578562896236934",
    "https://roblox.com.gr/games/122446657157717/CASE-UPDATE-Sniper-Arena?privateServerLinkCode=26676135374151735703107772519650&game_id=122446657157717&game_name=CASE-UPDATE-Sniper-Arena",
    "http://thrshopee155.blogspot.com/",
    "http://www.infoundianshopee31.blogspot.com/",
]

# Label rules are the published maps. They are not flipped to raise a score.
CANDIDATES = [
    {
        "name": "ilkayO/modernbert-phishing-detector",
        "slug": "ilkay_modernbert",
        "max_length": 256,
        "max_length_source": "model card quick-start uses truncation at 256; config max_position_embeddings is 8192 and has no max_length field",
        "positive": "index_1",
    },
    {
        "name": "kmack/malicious-url-detection",
        "slug": "kmack_distilbert",
        "max_length": 512,
        "max_length_source": "DistilBERT max_position_embeddings is 512; the full URL string is passed, not a domain-only slice",
        "positive": "label_name",
        "positive_names": ["MALWARE"],
        "negative_names": ["BENIGN"],
    },
    {
        "name": "r3ddkahili/final-complete-malicious-url-model",
        "slug": "r3ddkahili_bert",
        "max_length": 128,
        "max_length_source": "model card states max sequence length 128",
        "positive": "one_minus_benign",
        "class_names": {0: "Benign", 1: "Defacement", 2: "Phishing", 3: "Malware"},
        "class_name_source": "README example. config.json only stores LABEL_0 through LABEL_3",
    },
]


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


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


def apply_threshold(rows: list[dict], threshold: float) -> list[dict]:
    scored = []
    for row in rows:
        predicted = "phishing" if row["p_phishing"] >= threshold else "legitimate"
        scored.append({**row, "predicted_label": predicted, "threshold": threshold})
    return scored


def choose_threshold(rows: list[dict]) -> dict:
    """Same validation rule as evaluate_robustness.py. Test rows are not passed in."""
    base = metrics(apply_threshold(rows, 0.50))
    eligible = []
    table = []
    for threshold in CANDIDATE_THRESHOLDS:
        stats = metrics(apply_threshold(rows, threshold))
        table.append({"threshold": threshold, **stats})
        recall_ok = (
            stats["recall_phishing"] >= 0.85
            and stats["recall_phishing"] >= base["recall_phishing"] - 0.05 - 1e-12
        )
        if recall_ok:
            eligible.append((stats["false_positive_rate"], -stats["f1_phishing"], threshold, stats))
    if not eligible:
        return {
            "threshold": 0.50,
            "reason": "no candidate kept recall within 5 points of the 0.50 operating point and at least 0.85",
            "validation_curve": table,
            "validation_at_threshold": base,
        }
    eligible.sort()
    _fpr, _neg_f1, threshold, stats = eligible[0]
    return {
        "threshold": threshold,
        "reason": "lowest validation false-positive rate subject to the recall constraint",
        "validation_curve": table,
        "validation_at_threshold": stats,
    }


def select_model(validation_choices: list[dict]) -> dict:
    """Pick from validation operating points only."""
    eligible = [
        choice
        for choice in validation_choices
        if choice["validation_at_threshold"]["recall_phishing"] >= 0.85
    ]
    pool = eligible or validation_choices
    pool = sorted(
        pool,
        key=lambda choice: (
            choice["validation_at_threshold"]["false_positive_rate"],
            -choice["validation_at_threshold"]["f1_phishing"],
            choice["threshold"],
            choice["name"],
        ),
    )
    winner = pool[0]
    return {
        "name": winner["name"],
        "threshold": winner["threshold"],
        "pool": "recall_at_least_0.85" if eligible else "no model met the recall gate; lowest validation false-positive rate among all",
        "validation_false_positive_rate": winner["validation_at_threshold"]["false_positive_rate"],
        "validation_recall": winner["validation_at_threshold"]["recall_phishing"],
        "validation_f1": winner["validation_at_threshold"]["f1_phishing"],
    }


def category_table(rows: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        key = f"{row['expected_label']}:{row.get('category') or 'uncategorized'}"
        grouped.setdefault(key, []).append(row)
    return {key: metrics(grouped[key]) for key in sorted(grouped)}


def compact_errors(rows: list[dict]) -> list[dict]:
    errors = []
    for row in rows:
        if row["expected_label"] == row["predicted_label"]:
            continue
        errors.append(
            {
                "url": row["url"],
                "expected_label": row["expected_label"],
                "predicted_label": row["predicted_label"],
                "category": row.get("category", ""),
                "p_phishing": round(row["p_phishing"], 4),
                "p_legitimate": round(row["p_legitimate"], 4),
                "argmax_label": row.get("argmax_label", ""),
                "n_tokens": row.get("n_tokens"),
                "truncated": row.get("truncated"),
            }
        )
    return errors


def draw_matrix(counts: dict, path: Path, title: str) -> None:
    for expected in ("phishing", "legitimate"):
        for predicted in ("phishing", "legitimate"):
            counts.setdefault((expected, predicted), 0)
    grid = [
        [counts[("phishing", "phishing")], counts[("phishing", "legitimate")]],
        [counts[("legitimate", "phishing")], counts[("legitimate", "legitimate")]],
    ]
    image = Image.new("RGB", (760, 460), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((24, 18), title[:90], fill="black", font=font)
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


def positive_probability(spec: dict, model, probs: torch.Tensor) -> tuple[float, str, dict]:
    labels = {int(index): str(name) for index, name in model.config.id2label.items()}
    as_float = {index: float(probs[index].item()) for index in range(probs.shape[-1])}
    if spec["positive"] == "index_1":
        if 1 not in as_float:
            raise RuntimeError(f"{spec['name']} has no class index 1; labels={labels}")
        phishing = as_float[1]
        argmax = max(as_float, key=as_float.get)
        return phishing, labels.get(argmax, str(argmax)), {"id2label": labels, "class_probs": as_float}
    if spec["positive"] == "label_name":
        name_to_index = {name: index for index, name in labels.items()}
        missing = [name for name in spec["positive_names"] + spec["negative_names"] if name not in name_to_index]
        if missing:
            raise RuntimeError(f"{spec['name']} label map {labels} is missing {missing}")
        phishing = sum(as_float[name_to_index[name]] for name in spec["positive_names"])
        argmax = max(as_float, key=as_float.get)
        return phishing, labels[argmax], {"id2label": labels, "class_probs": as_float}
    if spec["positive"] == "one_minus_benign":
        config_names = set(labels.values())
        if config_names != {f"LABEL_{index}" for index in spec["class_names"]}:
            raise RuntimeError(
                f"{spec['name']} config labels {labels} do not match the expected unlabeled LABEL_0..3 map"
            )
        benign = as_float[0]
        phishing = 1.0 - benign
        argmax = max(as_float, key=as_float.get)
        return (
            phishing,
            spec["class_names"][argmax],
            {"id2label_config": labels, "class_probs": as_float, "readme_names": spec["class_names"]},
        )
    raise RuntimeError(spec["positive"])


def score_split(model, tokenizer, spec: dict, rows: list[dict]) -> tuple[list[dict], list[dict], float]:
    scored = []
    failures = []
    started = time.perf_counter()
    max_length = spec["max_length"]
    for row in rows:
        try:
            encoded = tokenizer(
                row["url"],
                return_tensors="pt",
                truncation=True,
                max_length=max_length,
            )
            token_ids = encoded["input_ids"][0].tolist()
            with torch.inference_mode():
                logits = model(**encoded).logits
            probs = torch.softmax(logits.float(), dim=-1)[0]
            p_phishing, argmax_label, _extra = positive_probability(spec, model, probs)
            decoded = tokenizer.decode(token_ids, skip_special_tokens=True)
            item = {
                **row,
                "p_phishing": p_phishing,
                "p_legitimate": 1.0 - p_phishing,
                "argmax_label": argmax_label,
                "n_tokens": len(token_ids),
                "truncated": len(token_ids) >= max_length,
                "decoded_matches_url": decoded == row["url"],
            }
            if row["url"] in FOCUS_URLS:
                item["tokens"] = tokenizer.convert_ids_to_tokens(token_ids)
                item["decoded"] = decoded
            scored.append(item)
        except Exception as exc:
            failures.append({"url": row["url"], "error": f"{type(exc).__name__}: {exc}"})
    elapsed = time.perf_counter() - started
    return scored, failures, elapsed


def load_candidate(spec: dict):
    """Load published weights. A torch.compile save uses an `_orig_mod.` prefix.

    `from_pretrained` treats those keys as unexpected and leaves the classifier
    randomly initialized. Strip that prefix and require an exact key match.
    """
    started = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(spec["name"])
    weight_path = Path(hf_hub_download(repo_id=spec["name"], filename="model.safetensors"))
    raw = load_file(str(weight_path))
    stripped = any(key.startswith("_orig_mod.") for key in raw)
    if stripped:
        raw = {key.removeprefix("_orig_mod."): value.float() for key, value in raw.items()}
    else:
        raw = {key: value.float() for key, value in raw.items()}
    config = AutoConfig.from_pretrained(spec["name"])
    try:
        model = AutoModelForSequenceClassification.from_config(config, attn_implementation="eager")
    except TypeError:
        model = AutoModelForSequenceClassification.from_config(config)
    model.load_state_dict(raw, strict=True)
    model.float()
    model.eval()
    elapsed = time.perf_counter() - started
    n_params = sum(parameter.numel() for parameter in model.parameters())
    labels = {int(index): str(name) for index, name in model.config.id2label.items()}
    model._phase4_revision = weight_path.parent.name
    model._phase4_weight_note = (
        "stripped _orig_mod. prefix; strict load_state_dict"
        if stripped
        else "strict load_state_dict of published keys"
    )
    return model, tokenizer, elapsed, n_params, labels


def rounded_rows(rows: list[dict], threshold: float) -> list[dict]:
    applied = apply_threshold(rows, threshold)
    output = []
    for row in applied:
        output.append(
            {
                "model_threshold": threshold,
                "url": row["url"],
                "expected_label": row["expected_label"],
                "predicted_label": row["predicted_label"],
                "p_phishing": f"{row['p_phishing']:.6f}",
                "p_legitimate": f"{row['p_legitimate']:.6f}",
                "argmax_label": row.get("argmax_label", ""),
                "split": row.get("split", ""),
                "category": row.get("category", ""),
                "verification_status": row.get("verification_status", ""),
                "n_tokens": row.get("n_tokens", ""),
                "truncated": row.get("truncated", ""),
                "model": row.get("model", ""),
            }
        )
    return output


def main() -> None:
    validation = read_csv(HERE / "robustness_validation.csv")
    test = read_csv(HERE / "robustness_test.csv")
    synthetic = read_csv(HERE / "robustness_synthetic.csv")
    primary = read_csv(HERE / "evaluation_dataset.csv")
    for row in primary:
        row.setdefault("category", "")
    overlap = {row["url"] for row in validation} & {row["url"] for row in test}
    if overlap:
        raise SystemExit(f"Validation and test share URLs: {sorted(overlap)[:3]}")

    report = {
        "device": "cpu",
        "torch": torch.__version__,
        "selection_rule": (
            "For each model, choose a threshold on robustness_validation.csv with the phase-3 rule. "
            "Then choose the model with the lowest validation false-positive rate among models whose "
            "validation recall is at least 0.85. Test rows are not an input to either choice."
        ),
        "models": {},
        "failures": [],
    }
    validation_choices = []
    held_scores: dict[str, dict] = {}
    partial_path = HERE / "phase4_partial.json"
    if partial_path.exists():
        partial = json.loads(partial_path.read_text(encoding="utf-8"))
        held_scores = partial.get("held_scores", {})
        report["failures"] = partial.get("failures", [])
        print(f"RESUMING {sorted(held_scores)}", flush=True)

    def save_partial() -> None:
        partial_path.write_text(
            json.dumps({"held_scores": held_scores, "failures": report["failures"]}, indent=2),
            encoding="utf-8",
        )

    for spec in CANDIDATES:
        if spec["name"] in held_scores:
            choice = held_scores[spec["name"]]["choice"]
            validation_choices.append(
                {
                    "name": spec["name"],
                    "threshold": choice["threshold"],
                    "validation_at_threshold": choice["validation_at_threshold"],
                }
            )
            print(f"SKIP {spec['name']}", flush=True)
            continue
        print(f"LOADING {spec['name']}", flush=True)
        try:
            model, tokenizer, load_s, n_params, labels = load_candidate(spec)
        except Exception:
            report["failures"].append({"name": spec["name"], "stage": "load", "traceback": traceback.format_exc()})
            print(f"LOAD FAILED {spec['name']}", flush=True)
            continue
        try:
            val_rows, val_fail, val_s = score_split(model, tokenizer, spec, validation)
            if val_fail:
                report["failures"].append({"name": spec["name"], "stage": "validation", "rows": val_fail})
            choice = choose_threshold(val_rows)
            validation_choices.append(
                {
                    "name": spec["name"],
                    "threshold": choice["threshold"],
                    "validation_at_threshold": choice["validation_at_threshold"],
                }
            )
            print(
                f"VALIDATION {spec['name']} threshold={choice['threshold']} "
                f"fpr={choice['validation_at_threshold']['false_positive_rate']:.3f} "
                f"recall={choice['validation_at_threshold']['recall_phishing']:.3f}",
                flush=True,
            )
            other = {}
            score_time = val_s
            for split_name, rows in (
                ("test", test),
                ("primary", primary),
                ("synthetic", synthetic),
            ):
                scored, failed, elapsed = score_split(model, tokenizer, spec, rows)
                score_time += elapsed
                if failed:
                    report["failures"].append({"name": spec["name"], "stage": split_name, "rows": failed})
                other[split_name] = scored
            probe = {}
            if spec["slug"] == "ilkay_modernbert":
                probe_rows, probe_fail, _elapsed = score_split(
                    model,
                    tokenizer,
                    spec,
                    [{"url": "https://secure-login-verify.suspicious-domain.tk/login", "expected_label": "card_example"}],
                )
                probe = {"card_example": probe_rows, "failures": probe_fail}
            held_scores[spec["name"]] = {
                "spec": spec,
                "load_seconds": load_s,
                "score_seconds": score_time,
                "n_params": n_params,
                "id2label": labels,
                "validation_rows": val_rows,
                "choice": choice,
                "other": other,
                "probe": probe,
                "do_lower_case": getattr(tokenizer, "do_lower_case", None),
                "revision": model._phase4_revision,
                "weight_load": model._phase4_weight_note,
            }
            save_partial()
            print(f"SAVED {spec['name']}", flush=True)
        except Exception:
            report["failures"].append({"name": spec["name"], "stage": "score", "traceback": traceback.format_exc()})
            print(f"SCORE FAILED {spec['name']}", flush=True)
        finally:
            del model
            del tokenizer
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    if not validation_choices:
        (HERE / "phase4_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise SystemExit("No candidate could be scored")

    selected = select_model(validation_choices)
    report["selected_from_validation"] = selected
    print(f"SELECTED {selected['name']} at {selected['threshold']}", flush=True)

    prediction_rows = []
    for name, bundle in held_scores.items():
        spec = bundle["spec"]
        choice = bundle["choice"]
        threshold = choice["threshold"]
        sections = {}
        for split_name, rows in (
            ("validation", bundle["validation_rows"]),
            ("test", bundle["other"]["test"]),
            ("primary", bundle["other"]["primary"]),
            ("synthetic", bundle["other"]["synthetic"]),
        ):
            at_default = apply_threshold(rows, 0.50)
            at_chosen = apply_threshold(rows, threshold)
            verified = split_name != "synthetic"
            entry = {
                "n_scored": len(rows),
                "at_0_50": metrics(at_default) if verified else "excluded_from_verified_metrics",
                "at_validation_threshold": metrics(at_chosen) if verified else "excluded_from_verified_metrics",
            }
            if split_name == "test":
                entry["categories_at_validation_threshold"] = category_table(at_chosen)
                entry["errors_at_validation_threshold"] = compact_errors(at_chosen)
                entry["errors_at_0_50"] = compact_errors(at_default)
                entry["any_truncated"] = any(row["truncated"] for row in rows)
                entry["max_tokens"] = max((row["n_tokens"] for row in rows), default=0)
                counts = Counter((row["expected_label"], row["predicted_label"]) for row in at_chosen)
                draw_matrix(
                    counts,
                    HERE / f"phase4_{spec['slug']}_test_confusion_matrix.png",
                    f"{spec['slug']} robustness test t={threshold}",
                )
            if split_name == "primary":
                entry["errors_at_validation_threshold"] = compact_errors(at_chosen)
            if split_name == "synthetic":
                entry["rows"] = [
                    {
                        "url": row["url"],
                        "expected_label": row["expected_label"],
                        "verification_status": row["verification_status"],
                        "p_phishing": round(row["p_phishing"], 4),
                        "predicted_at_0_50": "phishing" if row["p_phishing"] >= 0.50 else "legitimate",
                        "argmax_label": row["argmax_label"],
                    }
                    for row in rows
                ]
            sections[split_name] = entry
            tagged = []
            for row in apply_threshold(rows, threshold):
                tagged.append({**row, "model": name, "split": row.get("split") or split_name})
            prediction_rows.extend(rounded_rows(tagged, threshold))

        focus = []
        by_url = {}
        for split_name, rows in (
            ("validation", bundle["validation_rows"]),
            ("test", bundle["other"]["test"]),
            ("primary", bundle["other"]["primary"]),
        ):
            for row in rows:
                by_url[row["url"]] = (split_name, row)
        for url in FOCUS_URLS:
            found = by_url.get(url)
            if not found:
                focus.append({"url": url, "found": False})
                continue
            split_name, row = found
            focus.append(
                {
                    "url": url,
                    "found": True,
                    "split": split_name,
                    "expected_label": row["expected_label"],
                    "p_phishing": round(row["p_phishing"], 4),
                    "predicted_at_0_50": "phishing" if row["p_phishing"] >= 0.50 else "legitimate",
                    "predicted_at_validation_threshold": (
                        "phishing" if row["p_phishing"] >= threshold else "legitimate"
                    ),
                    "argmax_label": row["argmax_label"],
                    "n_tokens": row["n_tokens"],
                    "truncated": row["truncated"],
                    "decoded_matches_url": row["decoded_matches_url"],
                    "decoded": row.get("decoded", ""),
                    "tokens": row.get("tokens", []),
                }
            )

        n_scored = sum(len(bundle["other"][key]) for key in ("test", "primary", "synthetic")) + len(
            bundle["validation_rows"]
        )
        report["models"][name] = {
            "preprocessing": {
                "max_length": spec["max_length"],
                "max_length_source": spec["max_length_source"],
                "positive_rule": spec["positive"],
                "class_name_source": spec.get("class_name_source", "config id2label"),
                "do_lower_case": bundle["do_lower_case"],
                "input": "URL string from the CSV, unchanged",
            },
            "id2label": bundle["id2label"],
            "revision": bundle["revision"],
            "weight_load": bundle["weight_load"],
            "n_params": bundle["n_params"],
            "load_seconds": round(bundle["load_seconds"], 3),
            "score_seconds": round(bundle["score_seconds"], 3),
            "milliseconds_per_url": round(1000 * bundle["score_seconds"] / n_scored, 2) if n_scored else None,
            "n_scored": n_scored,
            "validation_threshold": {
                "threshold": choice["threshold"],
                "reason": choice["reason"],
                "validation_curve": choice["validation_curve"],
            },
            "splits": sections,
            "focus_urls": focus,
            "card_example_probe": bundle["probe"],
        }

    (HERE / "phase4_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    fieldnames = [
        "model_threshold",
        "url",
        "expected_label",
        "predicted_label",
        "p_phishing",
        "p_legitimate",
        "argmax_label",
        "split",
        "category",
        "verification_status",
        "n_tokens",
        "truncated",
        "model",
    ]
    # rounded_rows does not include model. Rebuild with model attached above via tagged row.
    # The helper copies known keys only, so add model into the row before calling it.
    with (HERE / "phase4_predictions.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in prediction_rows:
            writer.writerow(row)
    print("WROTE phase4_metrics.json", flush=True)


if __name__ == "__main__":
    main()
