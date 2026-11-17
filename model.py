import torch
import logging
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from functools import lru_cache

# Suppress transformers info logs (including BOS/EOS config warnings)
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
logging.getLogger("transformers.configuration_utils").setLevel(logging.ERROR)

REPO = "CrabInHoney/urlbert-tiny-v6"
REVISION = "020744435b3be870dabb2bba0b41237bea69b84b"
HEAD = "ealvaradob_phishing_dataset"
# This head is the opposite of the PhiUSIIL head. Do not read class 0 as phishing.
EXPECTED_LABELS = {0: "legitimate", 1: "phishing"}


@lru_cache(maxsize=1)
def load_model_and_tokenizer():
    """Load tokenizer and model, cached for reuse."""
    tokenizer = AutoTokenizer.from_pretrained(REPO, revision=REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(
        REPO,
        revision=REVISION,
        subfolder=f"heads/{HEAD}",
        trust_remote_code=True
    )
    model.eval()
    labels = {int(index): str(name).lower() for index, name in model.config.id2label.items()}
    if labels != EXPECTED_LABELS:
        raise RuntimeError(
            f"Refusing to score with label map {labels}. "
            f"Expected {EXPECTED_LABELS} for head {HEAD}."
        )

    # Fix BOS/EOS token IDs if they exceed vocabulary size (tokenizer config issue)
    vocab_size = tokenizer.vocab_size
    if tokenizer.bos_token_id is not None and tokenizer.bos_token_id >= vocab_size:
        tokenizer.bos_token_id = None
    if tokenizer.eos_token_id is not None and tokenizer.eos_token_id >= vocab_size:
        tokenizer.eos_token_id = None

    return model, tokenizer


def predict_url(url: str) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Returns:
        dict with keys: label, confidence, probabilities, error
    """
    try:
        if not url or not url.strip():
            return {"error": "Please enter a URL to scan."}

        url = url.strip()

        # Basic URL format validation
        if not (url.startswith("http://") or url.startswith("https://")):
            return {"error": "URL must start with http:// or https://"}

        model, tokenizer = load_model_and_tokenizer()

        inputs = tokenizer(
            url,
            return_tensors="pt",
            truncation=True,
            max_length=model.config.max_length
        )

        with torch.no_grad():
            outputs = model(**inputs)

        probabilities = torch.softmax(outputs.logits, dim=-1)[0]
        labels = {int(index): str(name).lower() for index, name in model.config.id2label.items()}
        named = {labels[index]: float(probabilities[index].item()) for index in labels}
        if set(named) != {"phishing", "legitimate"}:
            return {"error": f"Unexpected label map: {labels}"}

        prediction = int(probabilities.argmax().item())
        predicted_label = labels[prediction]
        confidence = named[predicted_label] * 100

        return {
            "label": predicted_label,
            "confidence": round(confidence, 2),
            "probabilities": {
                "phishing": round(named["phishing"] * 100, 2),
                "legitimate": round(named["legitimate"] * 100, 2)
            },
            "error": None
        }

    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}


def get_model_info() -> dict:
    """Return model metadata for display."""
    model, tokenizer = load_model_and_tokenizer()
    return {
        "repo": REPO,
        "revision": REVISION,
        "head": HEAD,
        "labels": {int(index): str(name).lower() for index, name in model.config.id2label.items()},
        "max_length": model.config.max_length,
        "vocab_size": tokenizer.vocab_size,
        "model_type": model.config.model_type
    }