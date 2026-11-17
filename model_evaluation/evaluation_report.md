# URLBERT evaluation

Model under test: `CrabInHoney/urlbert-tiny-v6`, head `phiusiil_phishing_url`, called only through the existing `predict_url()`. Nothing in `model.py`, `app.py`, or the frontend was changed.

Positive class for precision, recall, and F1 is **phishing**.

## What was scored

`evaluation_dataset.csv` has 100 primary URLs: 50 legitimate and 50 phishing. No row was requested over the network.

| Set | n | Source | How sure the label is |
|---|---|---|---|
| Legitimate | 50 | Published public web addresses | The addresses are real public sites. The pages were not fetched in this run, and this is not a random sample of the web. |
| Phishing | 50 | OpenPhish public feed retrieved 2026-11-17 | Vendor-feed labels. Pages were not visited and were not re-checked by hand. |

Selection rules for the phishing half, applied in feed order to unique hosts:

- at least 20 HTTPS, 15 HTTP, 15 with a path, 8 with a query, 10 hosts containing a hyphen, 20 with a subdomain label, 6 containing a suspicious keyword, 4 long URLs, 3 short URLs
- then filled to 50

The resulting phishing half contains 30 HTTPS, 20 HTTP, 27 with a path, 8 with a query, 24 hyphenated hosts, 40 with a subdomain, and 7 keyword hits. It contains **no IP-address hosts**. That day's OpenPhish snapshot had 300 URLs and zero IP hosts, so IP behavior was not measured. No synthetic URL was labeled phishing.

The Tranco top-1m list was downloaded and then discarded. Many top entries are CDNs, telemetry hosts, or opaque names, so popularity was not used as a legitimate label.

The author reports 99.86% accuracy for this head on the PhiUSIIL test split. That number is not the result below.

## Primary results

| Metric | Value |
|---|---|
| Accuracy | 67% (67/100) |
| Precision (phishing) | 60.2% (50/83) |
| Recall (phishing) | 100% (50/50) |
| F1 (phishing) | 75.2% |
| False-positive rate | 66% (33/50 legitimate) |
| False-negative rate | 0% (0/50 phishing) |
| Runtime | About 4.4–4.8 s for 100 URLs, including the first model load (about 45 ms per URL). The exact figure is in `evaluation_metrics.json`. |

Confusion matrix (also `confusion_matrix.png`):

|  | Predicted phishing | Predicted legitimate |
|---|---|---|
| Expected phishing | 50 | 0 |
| Expected legitimate | 33 | 17 |

Re-run with `python model_evaluation/evaluate.py`. The script rewrites `evaluation_predictions.csv`, `evaluation_metrics.json`, and `confusion_matrix.png`.

## Legitimate URLs it got right

All 17 are bare `https://www.{name}/` homepages, with no path and no query. Confidence is 95.44% to 98.58%.

- https://www.google.com
- https://www.whatsapp.com
- https://www.microsoft.com
- https://www.wikipedia.org
- https://www.python.org
- https://www.mozilla.org
- https://www.cloudflare.com
- https://www.apple.com
- https://www.amazon.com
- https://www.nytimes.com
- https://www.nature.com
- https://www.un.org
- https://www.who.int
- https://www.nasa.gov
- https://www.irs.gov
- https://www.gov.uk
- https://www.rust-lang.org

## Legitimate URLs it called phishing

33 of 50. Every one of these is outside the bare `www` homepage shape. Confidence is 94.53% to 98.56%, and 26 of the 33 are at or above 98%.

Non-`www` hosts, including real product and login hosts:

- https://web.whatsapp.com
- https://github.com
- https://github.com/python/cpython
- https://maps.google.com
- https://accounts.google.com
- https://drive.google.com
- https://login.microsoftonline.com
- https://learn.microsoft.com/en-us/windows/
- https://docs.python.org/3/library/urllib.parse.html
- https://pypi.org/project/pip/
- https://developer.mozilla.org/en-US/docs/Web/HTTP
- https://blog.cloudflare.com
- https://news.ycombinator.com
- https://arxiv.org/abs/1701.06234
- https://cdn.jsdelivr.net/npm/react/package.json
- https://ftp.gnu.org/gnu/
- https://old.reddit.com
- https://outlook.live.com
- http://neverssl.com
- http://info.cern.ch/hypertext/WWW/TheProject.html

`www` hosts that add a path or query:

- https://www.google.com/search?q=weather
- https://www.w3.org/TR/url/
- https://www.rfc-editor.org/rfc/rfc3986
- https://support.apple.com/en-us
- https://www.bbc.com/news
- https://stackoverflow.com/questions
- https://www.npmjs.com/package/react
- https://www.youtube.com/watch?v=jNQXAC9IVRw
- https://www.iana.org/domains
- https://www.cloudflare.com/learning/dns/what-is-dns/
- https://en.wikipedia.org/wiki/Phishing
- https://en.wikipedia.org/wiki/URL?useskin=vector
- https://www.microsoft.com/en-us/windows

Cross-tab of the 50 legitimate URLs:

| Shape | Predicted legitimate | Predicted phishing |
|---|---|---|
| `www` host, no path and no query | 17 | 0 |
| `www` host, with a path or query | 0 | 9 |
| Any other host, no path and no query | 0 | 11 |
| Any other host, with a path or query | 0 | 13 |

## Phishing URLs it missed

None in this 50. That is not evidence that the head catches phishing in general. OpenPhish URLs in this sample are mostly non-`www` hosts, free-hosting names, paths, and queries. The only two that start with `www.` are `www.wwrreret264758.weebly.com` and `www.pemenang-shopee47.blogspot.com`. Both still have an extra host label, and both were flagged phishing at about 98.5%. This set does not contain a phishing URL shaped like `https://www.brand.tld/`.

## Confidence

Confidence does not separate correct decisions from mistakes.

| Group | n | Min | Median | Mean | At or above 98% |
|---|---|---|---|---|---|
| Legitimate, correct | 17 | 95.44 | 98.53 | 98.23 | 15 |
| Legitimate, false positive | 33 | 94.53 | 98.44 | 98.12 | 26 |
| Phishing, correct | 50 | 98.44 | 98.53 | 98.53 | 50 |
| Phishing, missed | 0 |  |  |  |  |

A 98% score appears on `https://www.google.com` and on `https://github.com`. The score is a saturated softmax, not a calibrated probability that the site is hostile.

## Where it is sensitive

These rates are inside this 100-URL set. Several slices are small.

| Slice | Errors |
|---|---|
| Legitimate with `www` | 9/26 (34.6%). All 9 have a path or query. |
| Legitimate without `www` | 24/24 |
| Legitimate with a path | 22/22 |
| Legitimate with a query | 3/3 |
| Legitimate HTTP | 2/2 (`neverssl.com`, `info.cern.ch`) |
| Legitimate HTTPS | 31/48 |
| Legitimate at or above the median length (35 characters) | 14/14 |
| Legitimate below that length | 19/36 |
| Legitimate containing a tracked brand string | 11/16 |
| Legitimate containing a hyphen | 6/7 |
| Legitimate containing login/verify/account-style words | 2/2 |
| Every phishing slice that had examples (HTTP, HTTPS, path, query, hyphen, keyword, subdomain) | 0 errors |
| IP-address URLs | not present |

Brand text is not the dividing line. `www.google.com` is accepted and `maps.google.com` is rejected. The split that holds with no exception in the legitimate half is: bare `https://www.{name}/` versus anything else.

Tokenization was not assumed to be the cause. Earlier inspection of `web.whatsapp.com` versus `www.whatsapp.com` showed the same `whatsapp` token and an intact URL string, with only the `web` versus `www` token changed. This larger set agrees with a host-shape failure, and it also fails `www` URLs once a path or query is added, which a single subdomain token does not explain.

## Limits

- Fifty vendor-labeled phishing URLs, unvisited. If OpenPhish is wrong about one of them, that row's label is wrong.
- Fifty famous public addresses, chosen to include paths, queries, HTTP, and non-`www` hosts. This raises the chance of exposing the homepage shortcut. It is not an estimate of the false-positive rate on all legitimate traffic.
- Real phishing is much rarer than 50%. A 66% false-positive rate on legitimate URLs would flag most ordinary links.
- No verified IP-address phishing URLs were available, so that case is unmeasured.
- No synthetic URL was given a phishing label.
