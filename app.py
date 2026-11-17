import streamlit as st
from model import predict_url, get_model_info
from link_sentry_component.link_sentry_component.component import link_sentry_component

print("[app.py] Module loaded", flush=True)

st.set_page_config(
    page_title="LinkSentry — AI-Powered URL Threat Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# The original page renders inside the component iframe. Remove the Streamlit
# shell so that page keeps its own black background, width, and scroll.
st.markdown("""
<style>
    #MainMenu, footer, header, [data-testid="stHeader"],
    [data-testid="stToolbar"], .stDeployButton { display: none !important; }

    .stApp, [data-testid="stAppViewContainer"],
    [data-testid="stMain"], section.main {
        background: #000000 !important;
    }

    [data-testid="stMainBlockContainer"], .block-container,
    [data-testid="stAppViewBlockContainer"] {
        max-width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
    }

    [data-testid="stVerticalBlock"],
    [data-testid="element-container"],
    .stElementContainer, .stCustomComponentV1 {
        margin: 0 !important;
        padding: 0 !important;
    }

    iframe.stCustomComponentV1 {
        border: none !important;
        width: 100% !important;
        display: block !important;
    }
</style>
""", unsafe_allow_html=True)


def main():
    # Initialize session state for scan results
    if "last_result" not in st.session_state:
        st.session_state.last_result = None
    if "last_request_id" not in st.session_state:
        st.session_state.last_request_id = 0

    # Call the custom component - this renders the original frontend in an iframe
    # Pass the last result as props so frontend can display it
    component_value = link_sentry_component(
        result=st.session_state.last_result,
        key="link_sentry_scanner"
    )

    # Handle scan requests from the frontend
    if component_value and isinstance(component_value, dict):
        action = component_value.get("action")
        url = component_value.get("url")
        request_id = component_value.get("requestId")

        if action == "scan" and url:
            # Deduplicate: only process if this is a new request
            if request_id != st.session_state.last_request_id:
                st.session_state.last_request_id = request_id
                
                st.session_state.last_result = predict_url(url.strip())
                st.rerun()


if __name__ == "__main__":
    main()