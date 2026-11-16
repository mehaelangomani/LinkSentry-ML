# LinkSentry-ML

Machine-learning-based phishing URL detection application built with Streamlit and a fine-tuned URLBERT model.

## Overview

LinkSentry analyses URL strings to detect phishing attempts using a transformer-based model. It never visits or loads the submitted websites — analysis is performed entirely on the URL structure and character patterns.

**Model:** `CrabInHoney/urlbert-tiny-v6` (classification head: `phiusiil_phishing_url`)  
**Labels:** 0 = phishing, 1 = legitimate

## Features

- Clean, modern single-page Streamlit interface
- Real-time phishing/legitimate classification with confidence scores
- Input validation and error handling
- Model and tokenizer cached for fast repeated scans
- Detailed probability breakdown for both classes
- Model information and disclaimer sections

## Installation

```bash
# Clone the repository
git clone https://github.com/mehaelangomani/LinkSentry-ML.git
cd LinkSentry-ML

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
streamlit run app.py
```

Then open http://localhost:8501 in your browser.

## Project Structure

```
LinkSentry-ML/
├── app.py              # Streamlit application
├── model.py            # Model loading and prediction logic
├── test_model.py       # Standalone model test script
├── requirements.txt    # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Model Details

The application uses a fine-tuned **URLBERT-tiny** model from Hugging Face:

- **Repository:** `CrabInHoney/urlbert-tiny-v6`
- **Classification Head:** `phiusiil_phishing_url`
- **Architecture:** Compact BERT variant optimised for URL classification
- **Training Data:** PhishTank, OpenPhish, and legitimate URL datasets (PhiUSIIL)
- **Max Sequence Length:** 128 tokens

The tokenizer's BOS/EOS token IDs (50281, 50282) originally exceeded the vocabulary size (8192). This is fixed at runtime in `model.py` by setting them to `None`, which prevents transformer warnings without modifying the model weights.

## Disclaimer

> **Model confidence ≠ accuracy.** The confidence score reflects how certain the model is about its prediction given its training, not the real-world probability that a URL is safe or malicious. LinkSentry is a supplementary aid, not a substitute for security best practices. Always verify suspicious URLs through multiple sources, keep software updated, and use comprehensive security solutions.

## License

MIT License — see LICENSE file for details.

## Acknowledgements

- Model by [CrabInHoney](https://huggingface.co/CrabInHoney) on Hugging Face
- Built with [Streamlit](https://streamlit.io), [PyTorch](https://pytorch.org), and [Transformers](https://huggingface.co/docs/transformers)