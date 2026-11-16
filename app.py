import streamlit as st
from model import predict_url, get_model_info

st.set_page_config(
    page_title="LinkSentry - Phishing URL Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    :root {
        --coral: #FF6B5B;
        --coral-dark: #E85545;
        --peach: #FFB39B;
        --peach-light: #FFD6C4;
        --pink: #FF8FA3;
        --pink-light: #FFC8D4;
        --white: #FFFFFF;
        --off-white: #FFF8F6;
        --dark: #2D2D2D;
        --gray: #6B6B6B;
        --light-gray: #E8E8E8;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .main {
        background-color: var(--off-white);
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 720px;
    }

    /* Header */
    .linksentry-header {
        text-align: center;
        padding: 1.5rem 0 0.5rem 0;
    }

    .linksentry-logo {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.25rem;
        letter-spacing: -0.5px;
    }

    .linksentry-tagline {
        font-size: 1.15rem;
        font-weight: 400;
        color: var(--gray);
        margin-bottom: 0;
        line-height: 1.5;
    }

    /* Scanner Card */
    .scanner-card {
        background: var(--white);
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 4px 24px rgba(255, 107, 91, 0.08), 0 1px 3px rgba(0, 0, 0, 0.04);
        border: 1px solid rgba(255, 179, 155, 0.3);
        margin-bottom: 1.5rem;
    }

    .input-label {
        font-size: 0.9rem;
        font-weight: 500;
        color: var(--dark);
        margin-bottom: 0.5rem;
        display: block;
    }

    .stTextInput > div > div > input {
        border-radius: 10px !important;
        border: 2px solid var(--light-gray) !important;
        padding: 0.875rem 1rem !important;
        font-size: 1rem !important;
        transition: all 0.2s ease !important;
        background-color: var(--off-white) !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: var(--coral) !important;
        box-shadow: 0 0 0 3px rgba(255, 107, 91, 0.15) !important;
        background-color: var(--white) !important;
    }

    .stTextInput > div > div > input::placeholder {
        color: var(--gray) !important;
        opacity: 0.6 !important;
    }

    /* Scan Button */
    .stButton > button {
        width: 100%;
        border-radius: 10px !important;
        background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%) !important;
        color: var(--white) !important;
        font-weight: 600 !important;
        font-size: 1.05rem !important;
        padding: 0.875rem 1.5rem !important;
        border: none !important;
        box-shadow: 0 4px 16px rgba(255, 107, 91, 0.3) !important;
        transition: all 0.2s ease !important;
        margin-top: 0.5rem !important;
    }

    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(255, 107, 91, 0.4) !important;
    }

    .stButton > button:active {
        transform: translateY(0);
    }

    .stButton > button:disabled {
        opacity: 0.6;
        transform: none;
    }

    /* Results */
    .result-card {
        background: var(--white);
        border-radius: 16px;
        padding: 2rem;
        box-shadow: 0 4px 24px rgba(255, 107, 91, 0.08), 0 1px 3px rgba(0, 0, 0, 0.04);
        border: 1px solid rgba(255, 179, 155, 0.3);
        margin-bottom: 1.5rem;
        animation: slideUp 0.3s ease-out;
    }

    @keyframes slideUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .result-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.625rem 1.25rem;
        border-radius: 50px;
        font-weight: 600;
        font-size: 1.1rem;
        margin-bottom: 1rem;
    }

    .result-phishing {
        background: linear-gradient(135deg, rgba(255, 107, 91, 0.15) 0%, rgba(255, 143, 163, 0.15) 100%);
        color: var(--coral-dark);
        border: 1px solid rgba(255, 107, 91, 0.3);
    }

    .result-legitimate {
        background: linear-gradient(135deg, rgba(76, 175, 80, 0.15) 0%, rgba(102, 187, 106, 0.15) 100%);
        color: #2E7D32;
        border: 1px solid rgba(76, 175, 80, 0.3);
    }

    .confidence-meter {
        margin-top: 1rem;
    }

    .confidence-label {
        display: flex;
        justify-content: space-between;
        font-size: 0.9rem;
        font-weight: 500;
        color: var(--dark);
        margin-bottom: 0.5rem;
    }

    .confidence-bar {
        height: 8px;
        background: var(--light-gray);
        border-radius: 4px;
        overflow: hidden;
    }

    .confidence-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.5s ease-out;
    }

    .confidence-phishing {
        background: linear-gradient(90deg, var(--coral) 0%, var(--pink) 100%);
    }

    .confidence-legitimate {
        background: linear-gradient(90deg, #4CAF50 0%, #66BB6A 100%);
    }

    .probabilities {
        display: flex;
        gap: 1rem;
        margin-top: 1.25rem;
        padding-top: 1.25rem;
        border-top: 1px solid var(--light-gray);
    }

    .prob-item {
        flex: 1;
        text-align: center;
        padding: 0.75rem;
        background: var(--off-white);
        border-radius: 10px;
    }

    .prob-value {
        font-size: 1.5rem;
        font-weight: 700;
        line-height: 1.2;
    }

    .prob-phishing .prob-value { color: var(--coral-dark); }
    .prob-legitimate .prob-value { color: #2E7D32; }

    .prob-label {
        font-size: 0.75rem;
        font-weight: 500;
        color: var(--gray);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 0.25rem;
    }

    /* Info Sections */
    .info-section {
        background: var(--white);
        border-radius: 16px;
        padding: 1.5rem;
        box-shadow: 0 2px 12px rgba(255, 107, 91, 0.05);
        border: 1px solid rgba(255, 179, 155, 0.2);
        margin-bottom: 1rem;
    }

    .info-title {
        font-size: 1rem;
        font-weight: 600;
        color: var(--dark);
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .info-title::before {
        content: "";
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: linear-gradient(135deg, var(--coral) 0%, var(--pink) 100%);
    }

    .info-text {
        font-size: 0.9rem;
        line-height: 1.6;
        color: var(--gray);
    }

    .info-text strong { color: var(--dark); }

    .info-list {
        margin: 0.5rem 0 0 1.25rem;
        padding: 0;
    }

    .info-list li {
        font-size: 0.875rem;
        line-height: 1.7;
        color: var(--gray);
        margin-bottom: 0.25rem;
    }

    .info-list li strong { color: var(--dark); }

    /* Disclaimer */
    .disclaimer {
        background: rgba(255, 179, 155, 0.15);
        border: 1px solid rgba(255, 179, 155, 0.3);
        border-radius: 10px;
        padding: 1rem;
        margin-top: 1rem;
        font-size: 0.8rem;
        color: var(--gray);
        line-height: 1.5;
    }

    .disclaimer strong { color: var(--coral-dark); }

    /* Footer */
    .footer {
        text-align: center;
        padding: 2rem 0 1rem 0;
        color: var(--gray);
        font-size: 0.8rem;
    }

    .footer a { color: var(--coral); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }

    /* Spinner */
    .stSpinner > div { border-top-color: var(--coral) !important; }
</style>
""", unsafe_allow_html=True)


def render_header():
    st.markdown("""
    <div class="linksentry-header">
        <div class="linksentry-logo">LinkSentry</div>
        <div class="linksentry-tagline">Think before you click. Scan before you trust.</div>
    </div>
    """, unsafe_allow_html=True)


def render_scanner():
    st.markdown('<div class="scanner-card">', unsafe_allow_html=True)

    st.markdown('<label class="input-label">Enter URL to scan</label>', unsafe_allow_html=True)

    url = st.text_input(
        "",
        placeholder="https://example.com",
        label_visibility="collapsed",
        key="url_input"
    )

    scan_clicked = st.button("Scan URL", type="primary", use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)

    return url, scan_clicked


def render_result(result: dict):
    if result.get("error"):
        st.html(f"""
        <div class="result-card" style="border-color: rgba(255, 107, 91, 0.5);">
            <div class="result-badge result-phishing">⚠ Error</div>
            <p style="color: var(--coral-dark); margin: 0;">{result["error"]}</p>
        </div>
        """)
        return

    label = result["label"]
    confidence = result["confidence"]
    probs = result["probabilities"]

    is_phishing = label == "phishing"

    badge_class = "result-phishing" if is_phishing else "result-legitimate"
    badge_icon = "🔴" if is_phishing else "🟢"
    badge_text = "Phishing Detected" if is_phishing else "Legitimate"

    fill_class = "confidence-phishing" if is_phishing else "confidence-legitimate"

    st.html(f"""
    <div class="result-card">
        <div class="result-badge {badge_class}">{badge_icon} {badge_text}</div>

        <div class="confidence-meter">
            <div class="confidence-label">
                <span>Model Confidence</span>
                <span>{confidence:.2f}%</span>
            </div>
            <div class="confidence-bar">
                <div class="confidence-fill {fill_class}" style="width: {confidence}%"></div>
            </div>
        </div>

        <div class="probabilities">
            <div class="prob-item prob-phishing">
                <div class="prob-value">{probs['phishing']:.2f}%</div>
                <div class="prob-label">Phishing</div>
            </div>
            <div class="prob-item prob-legitimate">
                <div class="prob-value">{probs['legitimate']:.2f}%</div>
                <div class="prob-label">Legitimate</div>
            </div>
        </div>
    </div>
    """)


def render_info_sections():
    model_info = get_model_info()

    st.markdown("""
    <div class="info-section">
        <div class="info-title">How It Works</div>
        <div class="info-text">
            LinkSentry uses a fine-tuned <strong>URLBERT</strong> model (a compact BERT variant trained specifically on URL strings) to classify URLs as phishing or legitimate. The model analyses the character-level patterns, structure, and linguistic features of the URL itself — <strong>it never visits or loads the website</strong>.
        </div>
        <ul class="info-list">
            <li>URL is tokenised into subword units</li>
            <li>Transformer encoder processes the sequence</li>
            <li>Classification head outputs probabilities for both classes</li>
            <li>Higher probability determines the prediction</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="info-section">
        <div class="info-title">Model Information</div>
        <div class="info-text">
            <strong>Repository:</strong> {model_info['repo']}<br>
            <strong>Classification Head:</strong> {model_info['head']}<br>
            <strong>Model Type:</strong> {model_info['model_type']}<br>
            <strong>Max Sequence Length:</strong> {model_info['max_length']} tokens<br>
            <strong>Vocabulary Size:</strong> {model_info['vocab_size']:,}<br>
            <strong>Labels:</strong> {model_info['labels'][0].title()} (0), {model_info['labels'][1].title()} (1)
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-section">
        <div class="info-title">Important Disclaimer</div>
        <div class="disclaimer">
            <strong>Model confidence ≠ accuracy.</strong> The confidence score reflects how certain the model is about its prediction given its training, not the real-world probability that the URL is safe or malicious. This tool is a <strong>supplementary aid</strong>, not a substitute for security best practices. Always verify suspicious URLs through multiple sources, keep software updated, and use comprehensive security solutions.
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_footer():
    st.markdown("""
    <div class="footer">
        LinkSentry &mdash; ML-based phishing URL detection &nbsp;|&nbsp;
        Model: <a href="https://huggingface.co/CrabInHoney/urlbert-tiny-v6" target="_blank">urlbert-tiny-v6</a> &nbsp;|&nbsp;
        Head: <code>phiusiil_phishing_url</code>
    </div>
    """, unsafe_allow_html=True)


def main():
    render_header()

    url, scan_clicked = render_scanner()

    if "last_result" not in st.session_state:
        st.session_state.last_result = None

    if scan_clicked:
        if not url or not url.strip():
            st.session_state.last_result = {"error": "Please enter a URL to scan."}
        else:
            with st.spinner("Analysing URL..."):
                result = predict_url(url)
                st.session_state.last_result = result

    if st.session_state.last_result:
        render_result(st.session_state.last_result)

    render_info_sections()
    render_footer()


if __name__ == "__main__":
    main()