# Alternative head: `ealvaradob_phishing_dataset`

Scored on the same 100 primary rows in `evaluation_dataset.csv`. No URL was added, removed, or edited. `model.py`, `app.py`, and the frontend were not changed. The PhiUSIIL head is still the production model.

Script: `python model_evaluation/evaluate_ealvaradob.py`

Outputs: `ealvaradob_predictions.csv`, `ealvaradob_metrics.json`, `ealvaradob_confusion_matrix.png`.

## What this head is

| Item | Finding |
|---|---|
| Repository | `CrabInHoney/urlbert-tiny-v6` |
| Revision | `020744435b3be870dabb2bba0b41237bea69b84b` |
| Head path | `heads/ealvaradob_phishing_dataset` |
| Encoder | `encoder_name_or_path` is `CrabInHoney/urlbert-tiny-v6`, hidden size 128. The loader copies that encoder in float16 and the forward pass casts token states back to float32 before the head. |
| Architecture | `SmartHeadForSequenceClassification`. Pooling is CLS concatenated with the masked mean, then absolute difference and product. Head width 256, dropout 0.15. This is the same module family as the PhiUSIIL head. |
| Head parameters | 396,802 (matches `training_meta.json`) |
| Encoder parameters | 2,033,408 |
| Weight footprint | About 1.6 MB for the head in float32, plus the shared encoder (about 4 MB in the float16 copy this loader builds). |
| Context used here | Head config `max_length` is 512. The longest URL in this CSV was 118 tokens. None were truncated. |
| Tokenizer | The shared URLBERT tokenizer. This run read `do_lower_case` as false and passed each CSV string through unchanged. |
| Label map | **0 = legitimate, 1 = phishing.** The PhiUSIIL head is the reverse: 0 = phishing, 1 = legitimate. |
| Training file named by the head | `ealvaradobphishing-dataset.csv`, columns `content` and `labels`, 20 epochs |
| Published score | Accuracy 0.9940 and loss 0.0965 on that file's own split (`training_meta.json`). That is not this external result. |
| Public dataset of the same name | `ealvaradob/phishing-dataset` mixes URLs, email, SMS, and HTML, with 0 = benign and 1 = phishing. The meta file does not prove this head saw only URLs. |
| License | Apache-2.0 on the `urlbert-tiny-v6` repository. |

The heads are not interchangeable. Production `predict_url()` stores `probabilities[0]` as phishing. On this head, index 0 is legitimate. Sending these weights through the current function would flip every label.

## Results on the same 100 URLs

Phishing is the positive class.

| Metric | PhiUSIIL head | ealvaradob head |
|---|---|---|
| Accuracy | 67% (67/100) | 88% (88/100) |
| Phishing precision | 60.2% (50/83) | 85.2% (46/54) |
| Phishing recall | 100% (50/50) | 92% (46/50) |
| Phishing F1 | 75.2% | 88.5% |
| False-positive rate | 66% (33/50) | 16% (8/50) |
| False-negative rate | 0% (0/50) | 8% (4/50) |

Confusion matrix for the ealvaradob head:

|  | Predicted phishing | Predicted legitimate |
|---|---|---|
| Expected phishing | 46 | 4 |
| Expected legitimate | 8 | 42 |

The accuracy increase is the drop from 33 false positives to 8, minus 4 phishing URLs the PhiUSIIL head had caught. Accuracy alone is not the decision. A scanner that still blocks ordinary sites, or that now misses phishing, is not automatically suitable.

## False positives

Eight legitimate URLs were called phishing.

| URL | Phishing probability | Legitimate probability |
|---|---|---|
| https://web.whatsapp.com | 97.44% | 2.56% |
| https://old.reddit.com | 98.55% | 1.45% |
| http://neverssl.com | 96.73% | 3.27% |
| https://cdn.jsdelivr.net/npm/react/package.json | 96.65% | 3.35% |
| https://news.ycombinator.com | 93.96% | 6.04% |
| https://login.microsoftonline.com | 88.30% | 11.70% |
| https://github.com | 87.71% | 12.29% |
| https://outlook.live.com | 82.43% | 17.57% |

`https://accounts.google.com` is classified legitimate at 98.19%. `https://github.com/python/cpython` is legitimate at 98.35%, while the `https://github.com` homepage is not. The bare-`www`-homepage shortcut from the PhiUSIIL run is not the rule here.

Legitimate URLs with a path: 1 error out of 22. That error is the jsDelivr package URL above. The PhiUSIIL head missed all 22.

Legitimate URLs with a query: 0 errors out of 3, including `https://www.google.com/search?q=weather` and the YouTube watch URL. The PhiUSIIL head missed all 3.

## False negatives

Four OpenPhish URLs were called legitimate. These labels come from the vendor feed. The pages were not visited.

| URL | Phishing probability | Legitimate probability |
|---|---|---|
| https://roblox.com.bz/games/82205993156224/Walk-10000-Stairs-for-Neko-Girl?privateServerLinkCode=01763772834170954578562896236934 | 2.23% | 97.77% |
| https://store.workshopcommunitybrowse.com/sharedfiles/filesdetails/id=3832495514/ | 4.16% | 95.84% |
| https://www.roblox.com.et/users/2717531752/profile | 6.53% | 93.47% |
| http://thrshopee155.blogspot.com/ | 29.61% | 70.39% |

Three of these are high-confidence misses. Recall is not preserved.

## Confidence

| Group | n | Min | Median | Mean | At or above 98% |
|---|---|---|---|---|---|
| Legitimate, correct | 42 | 52.60 | 98.19 | 95.65 | 23 |
| Legitimate, false positive | 8 | 82.43 | 96.65 | 92.72 | 1 |
| Phishing, correct | 46 | 55.70 | 98.38 | 96.28 | 31 |
| Phishing, missed | 4 | 70.39 | 95.84 | 89.37 | 0 |

Correct decisions still cluster near 98%. Mistakes are a little more spread out than under the PhiUSIIL head, where almost every score was about 98.5% whether it was right or wrong. They are not safe to treat as probabilities. `https://web.whatsapp.com` is still a 97.44% false positive, and one missed phishing URL is 97.77% legitimate.

## Speed and memory

Loading this head took 8.84 seconds, including the first download of the head files. Scoring the 100 URLs after that took 0.45 seconds, about 4.5 ms each.

That 4.5 ms figure is not a speedup over the PhiUSIIL baseline. The baseline timer included model load. Both heads use the same encoder and the same head width, so a Streamlit process that already holds URLBERT pays for one extra small head, not a second large model.

The process working-set reading in the script did not return a value. The weight sizes above are the reliable memory figures.

## Recommendation

1. False-positive performance improves on this set: 66% to 16%, and ordinary paths and queries are mostly accepted.
2. Phishing recall is not maintained: 100% to 92%, with three misses above 93% legitimate.
3. Confidence is less uniformly stuck at 98.5%, and it is still a poor measure of correctness.
4. Local cost matches the current app: same encoder, a 396,802-parameter head, Apache-2.0.
5. It can run inside the existing Streamlit process, but it is not a drop-in. The label indexes are reversed, so the current `predict_url()` mapping would invert every result. Remaining high-confidence errors mean it should not replace the production head until that swap is reviewed.

Leave the PhiUSIIL head in the application until you approve a change.
