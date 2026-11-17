# Alternatives to the current head

No replacement was downloaded. Figures below are the publishers' own numbers, not scores on `evaluation_dataset.csv`. The current head's 99.86% PhiUSIIL accuracy is the same kind of in-dataset number and did not hold on the external set in `evaluation_report.md`.

Current system, for scale: ModernBERT URL encoder, 2.03M parameters, hidden size 128, about 8 MB in FP32, 256-token window. The `phiusiil_phishing_url` head is a small classifier on that encoder. Local CPU inference in this run was about 48 ms per URL including the first load. Integration today is one `predict_url()` call.

## 1. Same encoder, head `ealvaradob_phishing_dataset`

| | |
|---|---|
| Architecture | Same URLBERT-tiny-v6 encoder, different classification head |
| Training data | EA phishing dataset (`ealvaradob/phishing-dataset`), not PhiUSIIL |
| Published metric | 99.40% accuracy, test loss 0.0965, on that dataset's own split |
| Size | Same encoder, head is small. No second backbone. |
| Speed and memory | Same order as the current app |
| Integration | Change the head subfolder passed to `from_pretrained`. Same tokenizer and `predict_url` shape. |
| License and availability | Public on `CrabInHoney/urlbert-tiny-v6`. Confirm the card license before redistribution. |

This is the smallest experiment that asks whether the failure is specific to the PhiUSIIL head. Its published accuracy can hide the same homepage shortcut, so it has to be scored on this CSV before it replaces anything.

## 2. `kmack/malicious-url-detection`

| | |
|---|---|
| Architecture | Transformer classifier, hidden size 768 |
| Training data | Malicious-URL corpus used by that model card (not PhiUSIIL) |
| Published metric | On the author's site-aware JPxxx URL benchmark: F1 0.9137, AUPRC 0.9626, AUROC 0.9903, FPR at 95% TPR of 0.0294. That benchmark is imbalanced (about 9:1 benign to malicious) and blocks the same registrable domain from appearing in two folds. |
| Size | BERT-class. Much larger than 2.03M parameters and much more than 8 MB. |
| Speed and memory | Noticeably slower and heavier on CPU than the tiny encoder. Still local. |
| Integration | Standard `AutoModelForSequenceClassification`. Label indexes must be checked before wiring it to the current results panel. |
| License and availability | Public Hugging Face weights. Confirm the card license. |

Useful because the published test tries not to leak the same site into train and test. That is the failure mode suggested by this evaluation. It is a poor first download: the cost is high before we know whether a different head on the current encoder already fixes the shortcut.

## 3. `ilkayO/modernbert-phishing-detector`

| | |
|---|---|
| Architecture | ModernBERT-base, about 149M parameters, hidden size much larger than 128 |
| Training data | Real-world URLs with deduplication, URL sanitization, and domain-grouped splits, per the model card |
| Published metric | F1 0.83, accuracy 83%, precision 0.84, recall 0.83 on unseen domains. The card treats scores above 0.85 as phishing and above 0.60 as suspicious. |
| Size | On the order of 0.1B parameters, BF16 weights |
| Speed and memory | Local, but a large step up from the tiny encoder |
| Integration | Standard Transformers load. Class index 1 is phishing in the card's example, which is the opposite of the current head. |
| License and availability | Apache-2.0, public weights |

This is the first candidate that publishes a moderate unseen-domain score instead of a 99% in-dataset score. Test it if the alternate tiny head still flags bare non-`www` hosts and ordinary paths.

## What to test first

Test head `ealvaradob_phishing_dataset` on the current encoder, using this same CSV and `evaluate.py`. Keep the PhiUSIIL head in place until that run is reviewed.

If that head still accepts only `https://www.{name}/` and rejects `https://github.com`, `https://web.whatsapp.com`, and normal paths, move to `ilkayO/modernbert-phishing-detector`. Use `kmack/malicious-url-detection` if a larger BERT-class model is acceptable and the ModernBERT card's 0.83 F1 is too low for the assignment.

Do not fine-tune `phiusiil_phishing_url` on more PhiUSIIL data. The author already reports 99.86% there, and this external set fails on URL shape rather than on a few missing brand names.
