# LinkSentry

LinkSentry is a local phishing-URL checker. You paste a URL into the original scanner page, and a small transformer model classifies the URL text as phishing or legitimate. The page is hosted by Streamlit. The app does not visit the website, call a paid API, or look up a live domain reputation.

## How the model works

The encoder is [CrabInHoney/urlbert-tiny-v6](https://huggingface.co/CrabInHoney/urlbert-tiny-v6), a ModernBERT URL model with about 2.03 million parameters. Production uses the classification head `ealvaradob_phishing_dataset` at revision `020744435b3be870dabb2bba0b41237bea69b84b`.

The head reads the URL string only. It does not check DNS, download the page, or inspect certificates. A high score means the model is confident in its own class, not that the website has been independently verified as safe.

Label map for this head:

- Class 0 = legitimate
- Class 1 = phishing

This is the opposite of the unused `phiusiil_phishing_url` head. `model.py` checks the loaded map before scoring and reads probabilities by class name.

## Technologies

- Streamlit, as the host
- The original HTML, CSS, and JavaScript page in `frontend_extracted/`
- PyTorch and Hugging Face Transformers
- The URLBERT-tiny encoder and the ealvaradob head, loaded from Hugging Face on first run

No API key is required. The first launch downloads the public weights into the local Hugging Face cache.

## Project structure

```
LinkSentry-ML/
├── app.py                         # Streamlit host
├── model.py                       # Load the head and run predict_url
├── test_model.py                  # Checks the label map and prints sample scans
├── requirements.txt
├── frontend_extracted/            # Original scanner page
├── link_sentry_component/         # Serves that page inside Streamlit
└── model_evaluation/              # Frozen datasets and evaluation reports
```

## Installation

```bash
git clone https://github.com/mehaelangomani/LinkSentry-ML.git
cd LinkSentry-ML
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

On Linux or macOS, activate the environment with `source venv/bin/activate`.

## Run locally

From the repository root:

```bash
streamlit run app.py
```

Open http://localhost:8501. The original black page with the coral scanner is what you should see. Paste a URL that starts with `http://` or `https://` and press Scan URL. An empty or invalid value stays in the page and shows an error. A valid URL is sent to `predict_url`, and the verdict, both class scores, and the model confidence appear in the original results section.

Check the wiring without the browser:

```bash
python test_model.py
```

## Example results

These are real outputs from `predict_url` on this head, not corrected labels. Confidence is the winning class score.

| URL | Prediction | Confidence | Phishing | Legitimate |
|---|---|---|---|---|
| https://www.google.com | legitimate | 97.88% | 2.12% | 97.88% |
| https://www.wikipedia.org | legitimate | 98.38% | 1.62% | 98.38% |
| https://web.whatsapp.com | phishing | 97.44% | 97.44% | 2.56% |
| https://github.com | phishing | 87.71% | 87.71% | 12.29% |
| http://paypal-secure-login.verify-account.com | phishing | 98.50% | 98.50% | 1.50% |

`web.whatsapp.com` and `github.com` are real sites. The model still flags them. That is a known false positive, not a rule added in the app.

The lookalike example is a hostname used only as a string. The app does not open it.

## Measured performance

On a held-out set of 79 URLs that the model did not use for threshold selection (`model_evaluation/robustness_test.csv`, default threshold 0.50):

| Metric | ealvaradob head | PhiUSIIL head, not used in the app |
|---|---|---|
| Accuracy | 87.3% | 51.9% |
| Precision | 87.2% | 50.6% |
| Recall | 87.2% | 100% |
| F1 | 87.2% | 67.2% |
| False-positive rate | 12.5% | 95.0% |
| False-negative rate | 12.8% | 0% |

The same head missed phishing URLs such as `roblox.com.bz` and `roblox.com.gr` while giving them a high legitimate score. Several ordinary login and documentation URLs are still false positives. Details are in `model_evaluation/robustness_report.md` and `model_evaluation/phase4_model_comparison.md`.

Three other local models were scored on the same test. None had a lower false-positive rate than this head. The published in-dataset accuracies near 99% did not hold on these files.

## Limitations

LinkSentry does not guarantee protection against phishing. It can miss a malicious URL and can flag a legitimate one, sometimes with confidence above 95%. Use the result as one signal. Do not treat a "legitimate" verdict as proof that a site is safe, and do not treat the confidence percentage as a calibrated probability.

The model weights are published under the Apache-2.0 license on the Hugging Face repository linked above.
