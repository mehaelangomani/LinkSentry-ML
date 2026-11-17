from pathlib import Path

import streamlit.components.v1 as components
from streamlit.runtime import get_instance
from streamlit.runtime.scriptrunner_utils.script_run_context import get_script_run_ctx

# Original self-contained page. Served by Streamlit's component file route,
# so the iframe does not depend on a Vite dev server or a v2 package manifest.
_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend_extracted"

_component_func = components.declare_component(
    "link_sentry_component",
    path=str(_FRONTEND_DIR),
)


def link_sentry_component(result=None, key=None):
    """
    Render the original LinkSentry page and return scan requests from it.

    Args:
        result: Prediction dict from model.predict_url, or None.
        key: Streamlit widget key.

    Returns:
        {action, url, requestId} after the user submits a URL, otherwise None.
    """
    # declare_component only registers when a script run is active. Re-register
    # the same object on each run so the iframe can be served from path=.
    if get_script_run_ctx() is not None:
        get_instance().component_registry.register_component(_component_func)

    return _component_func(result=result, key=key, default=None)