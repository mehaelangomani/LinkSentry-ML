"""Check production predict_url wiring. Does not assert that a URL is safe."""

from model import get_model_info, predict_url

EXAMPLES = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://web.whatsapp.com",
    "https://github.com",
    "http://paypal-secure-login.verify-account.com",
]


def main() -> None:
    info = get_model_info()
    print("Model:", info["repo"], info["revision"])
    print("Head:", info["head"])
    print("Labels:", info["labels"])
    if info["labels"] != {0: "legitimate", 1: "phishing"}:
        raise SystemExit("Label map is not 0=legitimate, 1=phishing")
    if info["head"] != "ealvaradob_phishing_dataset":
        raise SystemExit("Production head is not ealvaradob_phishing_dataset")

    empty = predict_url("   ")
    invalid = predict_url("notaurl")
    if not empty.get("error") or not invalid.get("error"):
        raise SystemExit(f"Validation failed: {empty} {invalid}")
    print("Empty input:", empty["error"])
    print("Invalid input:", invalid["error"])

    print("\n========== LINK SENTRY TEST RESULTS ==========")
    for url in EXAMPLES:
        result = predict_url(url)
        print("\nAnalysing URL:", url)
        if result.get("error"):
            raise SystemExit(f"Prediction failed for {url}: {result['error']}")
        phishing = result["probabilities"]["phishing"]
        legitimate = result["probabilities"]["legitimate"]
        if abs((phishing + legitimate) - 100) > 0.2:
            raise SystemExit(f"Probabilities do not sum to 100 for {url}: {result}")
        higher = "phishing" if phishing >= legitimate else "legitimate"
        if result["label"] != higher:
            raise SystemExit(f"Label does not match probabilities for {url}: {result}")
        if abs(result["confidence"] - max(phishing, legitimate)) > 0.2:
            raise SystemExit(f"Confidence does not match the winning class for {url}: {result}")
        print("Prediction:", result["label"])
        print("Confidence:", result["confidence"], "%")
        print("Phishing:", phishing, "%")
        print("Legitimate:", legitimate, "%")
    print("\n===============================================")
    print("All URL tests completed!")


if __name__ == "__main__":
    main()
