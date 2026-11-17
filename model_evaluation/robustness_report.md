# Robustness and generalization

The production files were not changed. The earlier reports are still in place. This run uses new URLs only.

Verified rows are disjoint from `evaluation_dataset.csv`. Phishing labels are the OpenPhish feed retrieved for this run. Pages were not requested. There were no IP-address phishing URLs in that feed, so verified IP phishing was not measured. Synthetic rows are in `robustness_synthetic.csv` and are not included in the accuracy figures below.

| Split | Role | Legitimate | Phishing |
|---|---|---|---|
| `robustness_validation.csv` | Choose a threshold only | 40 | 41 |
| `robustness_test.csv` | Report once, after the threshold is fixed | 40 | 39 |

Legitimate addresses are published public sites and were not fetched. The first item of each hand-listed pair went to validation and the second to test, before either model ran. Phishing URLs were shuffled with seed `20261117`, then split inside each category so both halves see the same kinds of URLs.

Both label maps were read from the loaded configs and checked before scoring:

| Head | Class 0 | Class 1 |
|---|---|---|
| PhiUSIIL | phishing | legitimate |
| ealvaradob | legitimate | phishing |

A prediction uses P(phishing) from the index named `phishing`, not from a fixed index.

## Previous ealvaradob errors

Tokenization used the shared URLBERT tokenizer. For 11 of the 12 earlier errors, decoding the tokens reproduces the URL. The Roblox `.bz` URL is the exception: the path is case-folded (`Walk` becomes `walk`) and long numbers are split. The host characters are still all present. None of the 12 were truncated.

The splits do not, by themselves, explain the mistakes. `github` becomes `g / ith / ub` on both the homepage the model rejects and the `/python/cpython` path it previously accepted. `whatsapp` is one token in `web.whatsapp.com`.

| URL | What the tokenizer did | Earlier ealvaradob result |
|---|---|---|
| https://web.whatsapp.com | `web`, `whatsapp`, `com` as whole tokens | Phishing, 97.44% |
| https://github.com | `g`, `ith`, `ub` | Phishing, 87.71% |
| https://login.microsoftonline.com | `login`, `microsoft`, `online` | Phishing, 88.30% |
| http://neverssl.com | `nev`, `ers`, `sl` | Phishing, 96.73% |
| https://news.ycombinator.com | `y`, `com`, `bin`, `ator` | Phishing, 93.96% |
| https://cdn.jsdelivr.net/npm/react/package.json | `js`, `deli`, `vr`, `re`, `act` | Phishing, 96.65% |
| https://old.reddit.com | `red`, `dit` | Phishing, 98.55% |
| https://outlook.live.com | `out`, `look` | Phishing, 82.43% |
| https://store.workshopcommunitybrowse.com/... | many whole words plus a split id | Legitimate, 95.84% |
| https://roblox.com.bz/games/... | `ro blo x . com . bz` and `/games` | Legitimate, 97.77% |
| http://thrshopee155.blogspot.com/ | `thr`, `shop`, `ee`, `blogs`, `pot` | Legitimate, 70.39% |
| https://www.roblox.com.et/users/... | `www . ro blo x . com . et` | Legitimate, 93.47% |

### Why `roblox.com.bz` was 97.77% legitimate

`roblox` is not one vocabulary word. The host is the pieces `ro`, `blo`, `x`, `.`, `com`, `.`, `bz`. Those first host pieces are the same ones in the real site.

These three real Roblox addresses were scored only as a comparison. They are not in the verified metrics.

| URL | PhiUSIIL P(phishing) | ealvaradob P(legitimate) |
|---|---|---|
| https://www.roblox.com/ | 98.46% | 96.44% |
| https://www.roblox.com/games | 98.02% | 98.57% |
| https://roblox.com/ | 98.51% | 88.40% |

The phishing URL adds `.bz` and a long `/games/...` path. ealvaradob already gives the real `/games` path 98.57% legitimate. The extra `.bz` token did not overcome that. PhiUSIIL calls the real Roblox host phishing at about 98%, so this miss belongs to the ealvaradob head, not to a shared encoder rule.

## Held-out test at the default 0.50 threshold

Phishing is the positive class. n = 79.

| Metric | PhiUSIIL | ealvaradob |
|---|---|---|
| Accuracy | 51.9% (41/79) | 87.3% (69/79) |
| Precision | 50.6% (39/77) | 87.2% (34/39) |
| Recall | 100% (39/39) | 87.2% (34/39) |
| F1 | 67.2% | 87.2% |
| False-positive rate | 95.0% (38/40) | 12.5% (5/40) |
| False-negative rate | 0% (0/39) | 12.8% (5/39) |

PhiUSIIL’s two correct legitimate URLs on this split were `https://www.nih.gov/` and `https://pubmed.ncbi.nlm.nih.gov/?term=phishing`. The other 38 legitimate URLs were phishing, including every login page, every path, both resolver IPs, and `https://tinyurl.com/`.

ealvaradob false positives, all still high confidence:

| URL | Category | P(phishing) |
|---|---|---|
| https://status.aws.amazon.com/ | subdomain | 98.39% |
| https://8.8.8.8/ | ip | 98.09% |
| https://signin.aws.amazon.com/ | login | 97.42% |
| https://datatracker.ietf.org/ | homepage | 95.11% |
| https://9.9.9.9/ | ip | 87.04% |

Four of the five are at or above 90%, and two are at or above 98%.

ealvaradob false negatives:

| URL | Category in the file | Notes |
|---|---|---|
| http://pulsebux.com/ | http | Plain HTTP host |
| http://www.bradescoempresabanking.com/ | http | Vendor-labeled. Looks like a bank hostname. Not visited. |
| http://www.infoundianshopee31.blogspot.com/ | http | Blogspot host |
| https://achiit.github.io/dukaan-is-hh/ | lookalike | Brand string on a non-official suffix |
| https://roblox.com.gr/games/...?privateServerLinkCode=... | long | Also tagged lookalike. Length was the category used in the table because the category rule checks length before the lookalike tag. |

Two of those five misses are at or above 90% legitimate: the Blogspot host at 94.82% and the `roblox.com.gr` URL at 95.64%. The github.io page is 84.95% legitimate. `pulsebux.com` and the Bradesco-like host are lower, at 61.97% and 66.94% legitimate. The median winning probability on the five misses is 84.95%.

### By category, default threshold, test split

| Category | PhiUSIIL | ealvaradob |
|---|---|---|
| Legitimate login (8) | 0/8 correct | 7/8 correct. Miss: AWS sign-in. |
| Legitimate subdomain (8) | 0/8 | 7/8. Miss: AWS status host. |
| Legitimate path (8) | 0/8 | 8/8 |
| Legitimate query (5) | 1/5 | 5/5 |
| Legitimate long path (2) | 0/2 | 2/2 |
| Legitimate homepage (6) | 1/6 | 5/6. Miss: IETF datatracker. |
| Legitimate shortener homepage (1) | 0/1 | 1/1 |
| Legitimate IP (2) | 0/2 | 0/2 |
| Phishing path, query, subdomain, https, shortener | 0 misses | 0 misses |
| Phishing lookalike tag used as the category (5) | 0 misses | 1 miss, the github.io page |
| Phishing long (4) | 0 misses | 1 miss, the long `roblox.com.gr` URL, which is also tagged lookalike |
| Phishing plain HTTP (6) | 0 misses | 3 misses |

Paths and queries, which broke PhiUSIIL, are handled by ealvaradob on this split. Lookalike hosts and plain HTTP hosts are where ealvaradob still fails. Both heads flag the two public resolver IPs.

No verified row was truncated. The longest test URL was 169 tokens. The ealvaradob head allows 512 and the PhiUSIIL head allows 256, so the length cap did not separate them here.

## Thresholds

The rule was fixed before the test scores were used. Predict phishing when P(phishing) is at least t. On validation only, keep t if recall stays at least 0.85 and no more than 0.05 below the recall at 0.50. Among the survivors, pick the lowest false-positive rate.

PhiUSIIL validation recall stayed 100% from 0.50 through 0.95. False-positive rate only moved from 95.0% to 87.5%, at t = 0.95. That was the selected threshold. On the test set it cut false positives from 38 to 35. Recall stayed 100%. The scores sit near 98.5% for both correct phishing calls and false positives (33 of 38 test false positives are at or above 98%). A threshold cannot separate them.

ealvaradob validation at 0.50: accuracy 95.1%, false-positive rate 5.0%, recall 95.1%. The rule selected t = 0.65, where validation false-positive rate is 2.5% and recall is 90.2%. On the test set, t = 0.65 and t = 0.50 produce the same confusion matrix. No test URL had a phishing probability between 0.50 and 0.65. The validation gain did not show up on the held-out URLs.

An “uncertain” band also does not catch the important misses. On the ealvaradob test errors, four false positives and at least the Roblox-style miss are already above 90% for the wrong class. Sending only low-confidence predictions to review would leave those high-confidence mistakes as automatic decisions. It would still be useful as a display state, not as the fix.

## Synthetic probes

These are not verified metrics.

ealvaradob called `http://docs.github.com/` and `https://www.docs.github.com/` legitimate (90.5% and 97.7%). PhiUSIIL called the HTTP variant phishing at 98.5%.

On reserved-domain lookalikes, PhiUSIIL returned about 98.5% phishing for all three, which is the same score it gives legitimate sites. ealvaradob called `paypal.example.com` phishing at 57.0%, `accounts.google.example.com` legitimate at 61.9%, and `github.com.example.net` phishing at 94.0%. Constructed lookalikes are not reliably separated.

Both heads called the documentation-range IP probes and the unresolved `bitly.com/3example` path phishing at about 98%.

## Recommendation

Do not retain PhiUSIIL for user-facing decisions. On a second, disjoint set its false-positive rate is 95%, and moving the threshold to 0.95 only lowers that to 87.5%.

Do not replace it with ealvaradob yet. ealvaradob is the better of the two on this held-out set: false-positive rate 12.5% instead of 95%, and paths and queries are mostly accepted. Recall falls to 87.2%, and the misses include a Roblox lookalike at very high legitimate confidence. The same head already did that on `roblox.com.bz`. A threshold chosen on the validation split did not change the test result.

Investigate another model before any production swap, aimed at lookalike domains rather than another head that memorizes a brand’s subwords. `ilkayO/modernbert-phishing-detector` remains the next candidate from the comparison note, because its card reports an unseen-domain test instead of a 99% in-dataset score. It has not been run on these CSVs.

If a later model is deployed, show an uncertain or review state when the winning probability is modest. Do not expect that state to catch errors whose wrong-class probability is already above 95%. Leave both current heads out of `app.py` until you approve a replacement.
