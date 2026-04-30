"""Free-text sanitization helper for collector outputs.

Strips all HTML/markdown tags and tag content. Used by every collector's
to_event() before populating CollectedEvent.title and .summary, per the
M3a spec section 5.3.
"""

import re

import bleach

# Strip <script>...</script> blocks BEFORE bleach: bleach with tags=[] removes
# the <script> tags but keeps the inner JS as plain text. We don't want that.
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)


def clean_text(value: str | None) -> str:
    """Return value with HTML tags + script content stripped. Empty if None."""
    if not value:
        return ""
    no_scripts = _SCRIPT_RE.sub("", value)
    return bleach.clean(no_scripts, tags=[], strip=True)
