
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)

# Model details
REPO = "CrabInHoney/urlbert-tiny-v6"
HEAD = "phiusiil_phishing_url"

print("Loading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(REPO)

print("Loading phishing classification model...")

model = AutoModelForSequenceClassification.from_pretrained(
    REPO,
    subfolder=f"heads/{HEAD}",
    trust_remote_code=True
)

model.eval()

print("\nModel loaded successfully!")

# Display actual model labels
print("Model labels:", model.config.id2label)


# Multiple URLs to test
test_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.microsoft.com",
    "http://paypal-secure-login.verify-account.com",
    "http://login-bank-account-verify.example.com"
]


# Analyse each URL
print("\n========== LINK SENTRY TEST RESULTS ==========")

for url in test_urls:

    print("\nAnalysing URL:", url)

    # Convert URL into model inputs
    inputs = tokenizer(
        url,
        return_tensors="pt",
        truncation=True,
        max_length=model.config.max_length
    )

    # Run prediction
    with torch.no_grad():
        outputs = model(**inputs)

    # Calculate probabilities
    probabilities = torch.softmax(outputs.logits, dim=-1)[0]

    # Get prediction
    prediction = probabilities.argmax().item()

    predicted_label = model.config.id2label[prediction]

    confidence = probabilities[prediction].item() * 100

    # Display results
    print("Prediction:", predicted_label)
    print("Confidence:", round(confidence, 2), "%")

print("\n===============================================")
print("All URL tests completed!")


