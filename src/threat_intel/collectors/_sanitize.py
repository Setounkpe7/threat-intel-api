"""Free-text sanitization helper for collector outputs.

Strips all HTML/markdown tags and tag content. Used by every collector's
to_event() before populating CollectedEvent.title and .summary, per the
M3a spec section 5.3.
"""

import re

import nh3

# Strip <script>...</script> blocks BEFORE nh3 as defence-in-depth. nh3 already
# drops <script> bodies (script is in ammonia's default clean_content_tags),
# but the explicit pre-strip keeps the guarantee independent of nh3 defaults.
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)


def clean_text(value: str | None) -> str:
    """Return value with HTML tags + script content stripped. Empty if None."""
    if not value:
        return ""
    no_scripts = _SCRIPT_RE.sub("", value)
    # tags=set() => no tags allowed: strip every tag while keeping inner text,
    # the nh3 equivalent of bleach.clean(text, tags=[], strip=True).
    return nh3.clean(no_scripts, tags=set(), strip_comments=True)
