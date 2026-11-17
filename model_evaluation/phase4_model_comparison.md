# Phase 4: other phishing URL models

Three local models were scored on the frozen CSVs. Production files were not changed. None of these models beat the ealvaradob head on the held-out robustness test, so none is shortlisted for production testing.

An earlier `from_pretrained` load of `ilkayO/modernbert-phishing-detector` ignored the checkpoint. The file stores weights under torch.compile’s `_orig_mod.` prefix, and Transformers treated every key as unexpected. The numbers below come from a second load that strips that prefix and requires an exact `load_state_dict` match. The other two checkpoints matched their published keys directly. No URL failed inference. Synthetic rows are not included in the accuracy figures.

## Candidates

| | ilkayO | kmack | r3ddkahili |
|---|---|---|---|
| Repository | `ilkayO/modernbert-phishing-detector` | `kmack/malicious-url-detection` | `r3ddkahili/final-complete-malicious-url-model` |
| Revision | `230cf4088bb6e7bbe932ee0bb937400e4e3c3b13` | `258499831602e1aea6c1f00e8483b820dd14b391` | `1e47e821fa91edf617b828fb99963dc84edc61e3` |
| Architecture | ModernBERT-base, 22 layers, hidden 768 | DistilBERT, 6 layers, hidden 768 | BERT-base, 12 layers, hidden 768 |
| Parameters | 149,606,402 | 66,955,010 | 109,485,316 |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| Where it ran | CPU, float32, no paid API | CPU, float32, no paid API | CPU, float32, no paid API |
| Load time | 14.4 s | 233.9 s | 314.0 s |
| Score time | 10.7 s for 268 URLs (39.8 ms/URL) | 3.9 s for 268 URLs (14.7 ms/URL) | 7.6 s for 268 URLs (28.3 ms/URL) |

Load time includes reading the snapshot from the local Hugging Face cache. The r3ddkahili snapshot was downloaded during this run. The other two were already cached. These times are not a comparison with the tiny URLBERT encoder, which is about 2 million parameters.

Published training notes, which were not remeasured here:

- ilkayO: fine-tune of `answerdotai/ModernBERT-base` on PhiUSIIL plus a Kaggle malicious-URL set, with domain-grouped splits. The card reports 83% accuracy and 0.83 F1 on its own unseen-domain split. That number did not hold on our files.
- kmack: fine-tune of `distilbert-base-uncased` on `kmack/Phishing_urls`. The config calls the classes BENIGN and MALWARE. The card’s demo text says to type a domain name. This run passed the full URL string instead, so path and query were still visible to the model.
- r3ddkahili: BERT-base on the Kaggle malicious-URL set (benign, defacement, phishing, malware). The card reports about 98% validation accuracy on that set. `config.json` only names `LABEL_0` through `LABEL_3`.

## Labels

| Model | What was verified | Positive score used |
|---|---|---|
| ilkayO | `config.json` has no class names. After a correct weight load the config labels are `LABEL_0` and `LABEL_1`. The README sets phishing to index 1. The README’s own example URL, `https://secure-login-verify.suspicious-domain.tk/login`, scored 88.1% on index 1. That probe is not in our CSVs and was not used to flip the map. | P(index 1) |
| kmack | `config.json` says `0=BENIGN`, `1=MALWARE`. The loaded map matched that exactly. | P(MALWARE) |
| r3ddkahili | Loaded map is `LABEL_0`..`LABEL_3`, as in the config. The README example and an alphabetical encoding of the Kaggle names both put benign at index 0, and they disagree on indexes 2 and 3. The decision uses `1 - P(LABEL_0)`. Names for indexes 2 and 3 are not part of the score. Argmax names in the tables below are the README names and are labels for reading, not a second verified map. | 1 − P(index 0) |

Input strings were not rewritten, lowercased by our code, or filtered with a domain list. kmack and r3ddkahili use uncased WordPiece tokenizers, so their decoded text is lowercase and does not byte-match the CSV. ilkayO’s focus URLs decoded back to the original string. No verified row was truncated. Limits were 256, 512, and 128 tokens, taken from each card.

## How the threshold was chosen

`robustness_validation.csv` has 40 legitimate and 41 phishing URLs. `robustness_test.csv` has 40 legitimate and 39 phishing URLs. The original 100-URL file was scored only after the choice below and was not an input to it. The same rule as the robustness run was used: predict phishing when P(phishing) is at least t; keep t only when validation recall stays at least 0.85 and within 0.05 of the recall at 0.50; among those, take the lowest false-positive rate.

| Model | Validation at 0.50 | Chosen t | Validation at chosen t |
|---|---|---|---|
| ilkayO | Accuracy 55.6%, FPR 57.5%, recall 68.3% | 0.50, because recall never reached 0.85 | Same as 0.50 |
| kmack | Accuracy 82.7%, FPR 32.5%, recall 97.6% | 0.75 | Accuracy 82.7%, FPR 30.0%, recall 95.1%, F1 84.8% |
| r3ddkahili | Accuracy 48.1%, FPR 100%, recall 95.1% | 0.50 | Same as 0.50. FPR was still 100% at 0.95 |

Among models whose chosen point had recall of at least 0.85, kmack had the lowest validation false-positive rate (30% versus 100%). That is why it is the selected candidate inside this round. The test numbers were not used to change that choice.

## Held-out test

Phishing is the positive class. n = 79. Baselines are the earlier robustness run at 0.50, copied here for comparison and not recomputed.

| Metric | PhiUSIIL | ealvaradob | ilkayO t=0.50 | kmack t=0.75 | r3ddkahili t=0.50 |
|---|---|---|---|---|---|
| Accuracy | 51.9% | 87.3% | 55.7% | 81.0% | 45.6% |
| Precision | 50.6% | 87.2% | 54.2% | 76.1% | 47.4% |
| Recall | 100% | 87.2% | 66.7% | 89.7% | 92.3% |
| F1 | 67.2% | 87.2% | 59.8% | 82.4% | 62.6% |
| False-positive rate | 95.0% (38/40) | 12.5% (5/40) | 55.0% (22/40) | 27.5% (11/40) | 100% (40/40) |
| False-negative rate | 0% (0/39) | 12.8% (5/39) | 33.3% (13/39) | 10.3% (4/39) | 7.7% (3/39) |

Confusion matrices, rows true phishing then true legitimate, columns predicted phishing then predicted legitimate:

| Model | Matrix | Image |
|---|---|---|
| ilkayO | 26, 13 / 22, 18 | `phase4_ilkay_modernbert_test_confusion_matrix.png` |
| kmack | 35, 4 / 11, 29 | `phase4_kmack_distilbert_test_confusion_matrix.png` |
| r3ddkahili | 36, 3 / 40, 0 | `phase4_r3ddkahili_bert_test_confusion_matrix.png` |

kmack at 0.50 on this same test, reported only as a reference, was accuracy 77.2%, FPR 35.0%, recall 89.7%. Moving to the validation threshold of 0.75 cut false positives from 14 to 11 and did not add misses.

The original 100-URL file, at each model’s validation threshold: ilkayO accuracy 59.0%, FPR 60%, recall 78%; kmack accuracy 91.0%, FPR 14%, recall 96%; r3ddkahili accuracy 48.0%, FPR 100%, recall 96%. ealvaradob’s earlier result on that file was 88% accuracy, 16% false-positive rate, and 92% recall. kmack looks slightly better there. The held-out test does not agree, and the test is the comparison that was locked before these scores were read.

### Categories on the test split

kmack at 0.75 accepted every legitimate query and the one shortener homepage. It missed 4 of 8 legitimate login pages, both resolver IPs, and 3 of 6 plain HTTP phishing URLs. The five URLs whose category is lookalike were all caught. The long `roblox.com.gr` URL is stored as category `long` because length is checked before the lookalike tag, and that URL was missed.

ilkayO missed most plain HTTP phishing rows (5 of 6) and flagged 6 of 8 legitimate login pages and 6 of 8 legitimate paths. r3ddkahili flagged every legitimate category. It had no true negatives.

There were still no IP-address phishing URLs in the OpenPhish sample, so verified IP phishing was not measured. `https://8.8.8.8/` and `https://9.9.9.9/` are legitimate and were false positives for all three models.

## Errors that matter

| URL | Expected | ilkayO | kmack | r3ddkahili |
|---|---|---|---|---|
| https://web.whatsapp.com | legitimate | Phishing, 81.9% | Legitimate, 40.0% malware | Phishing, 99.9% |
| https://github.com | legitimate | Legitimate, 33.3% | Legitimate, 3.2% malware | Phishing, 99.9% |
| https://login.microsoftonline.com | legitimate | Phishing, 85.3% | Phishing, 99.3% malware | Phishing, 99.9% |
| https://signin.aws.amazon.com/ | legitimate | Phishing, 90.3% | Legitimate, 16.6% malware | Phishing, 99.7% |
| roblox.com.bz `/games/...` | phishing | Legitimate, 14.4% | Legitimate, 1.6% malware | Benign, 0.02% non-benign |
| roblox.com.gr `/games/...` | phishing | Legitimate, 18.3% | Legitimate, 4.5% malware | Benign, 0.03% non-benign |
| http://thrshopee155.blogspot.com/ | phishing | Legitimate, 15.3% | Phishing, 97.3% malware | Phishing, 99.8% |
| http://www.infoundianshopee31.blogspot.com/ | phishing | Legitimate, 13.3% | Phishing, 88.6% malware | Phishing, 99.9% |

None of these were truncated. ilkayO’s copies decoded to the original URL, so the misses are not a lost character or a cut-off token. kmack’s and r3ddkahili’s decodes differ because the tokenizers lowercase.

The confident mistakes are not low-confidence boundary cases:

- ilkayO assigns 90% or more to several real login and documentation URLs (`signin.aws.amazon.com`, PayPal sign-in, pandas, PostgreSQL, Docker, Apache httpd). The same model assigns under 20% to both Roblox lookalikes and to both Blogspot phishing URLs. The README probe at 88% shows index 1 does fire on an obvious fake host. On our rows it still treats brand-plus-odd-TLD paths as safe and ordinary `/login` and `/docs` URLs as phishing.
- kmack’s false positives at the chosen threshold are mostly real login pages and doc hosts, several above 97% malware: `login.live.com`, Discord login, Steam login, PayPal sign-in, `outlook.office.com`, `go.dev/doc`, and the PyTorch docs. `login.microsoftonline.com` is in that same group at 99.3%. `github.com`, `web.whatsapp.com`, and `signin.aws.amazon.com` are accepted. Both Roblox `/games` URLs are accepted as benign, at 1.6% and 4.5% malware. The Blogspot URLs that ealvaradob missed are caught. A threshold cannot repair a 1.6% score without calling almost everything legitimate.
- r3ddkahili assigns about 99.8% non-benign to ordinary legitimate URLs, including homepages, queries, and docs, and about 99.98% benign to the two Roblox lookalikes. Its published 98% accuracy is an in-dataset figure. On these files the operating point is “almost everything is malicious,” except the lookalike shape it was supposed to catch.

Synthetic probes stayed out of the metrics. kmack called the two synthetic GitHub host variants legitimate and the three reserved-domain lookalikes, both documentation-range IP probes, and the unresolved short link malicious. ilkayO called the GitHub variants phishing as well. r3ddkahili called all eight probes phishing, including the two variants marked legitimate. Those eight rows are not evidence about real phishing sites.

## Limitations

- ilkayO was trained in part on PhiUSIIL. Popular legitimate hosts may have been in that data. The OpenPhish URLs in the robustness files were retrieved on 2026-11-17, after this model’s April 2026 upload, so those particular feed URLs are unlikely to be memorized. The 83% card score is a different split and was not reproduced.
- kmack’s positive class is named MALWARE, and the training set is a phishing-URL collection. Full URLs were scored even though the card demo asks for a domain only. A domain-only rerun was not done, because that would drop the path and query this comparison is meant to keep.
- r3ddkahili’s class names for indexes 2 and 3 are not in the weight config. The false-positive rate does not depend on that ambiguity: every legitimate test URL had P(index 0) below 0.50, and both Roblox lookalikes had P(index 0) above 0.99.
- No model saw a verified phishing URL hosted on a raw IP. All three flagged the two public resolver addresses.
- Validation has 81 rows. kmack’s threshold step from 0.50 to 0.75 only moved validation FPR from 32.5% to 30%. That is a small sample.

## Recommendation

Reject `ilkayO/modernbert-phishing-detector` for this product. Held-out accuracy is 55.7% and the false-positive rate is 55%. It misses the Roblox and Blogspot cases at low phishing probability.

Reject `r3ddkahili/final-complete-malicious-url-model`. The false-positive rate is 100% on both the validation split and the test split, and the Roblox lookalikes are scored benign above 99.9%.

Reject `kmack/malicious-url-detection` as a production replacement. It is the best of these three under the validation rule, and it does accept `github.com`, `web.whatsapp.com`, and `signin.aws.amazon.com`. On the held-out test its false-positive rate is 27.5%, more than double ealvaradob’s 12.5%, and it still misses `roblox.com.gr` at 4.5% malware probability and the earlier `roblox.com.bz` URL at 1.6%. Those are confidently wrong. Do not shortlist it for a production trial.

Keep the current application model unchanged. ealvaradob remains the stronger of the models already measured on this test split, and the earlier robustness report still says it is not ready to ship. Another candidate has to beat that test false-positive rate without giving the Roblox lookalikes back as legitimate before it is worth integrating.
