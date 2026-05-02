# VHS tape for the README hero animation.
# Renders to docs/assets/screenshots/hero-demo.gif
# Run with:
#   docker run --rm -v "$PWD":/vhs ghcr.io/charmbracelet/vhs docs/assets/hero-demo.tape

Output docs/assets/screenshots/hero-demo.gif

Set FontSize 16
Set Width 1280
Set Height 640
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 28ms
Set Shell bash

# ---- Scene 1: top finance threats, last 24h --------------------------------
Type "# 1) Top 3 finance-relevant threats, last 24h"
Sleep 600ms
Enter

Type 'curl -s https://threat-intel-api-production.up.railway.app/api/v1/sectors/finance/dashboard \'
Enter
Type "  | jq '.top_24h[:3] | .[] | {cve: .external_id, score, cvss: .cvss_score}'"
Enter
Sleep 4500ms

# ---- Scene 2: subscribe a SIEM to the finance RSS feed ---------------------
Type "# 2) Subscribe a SIEM to the finance RSS feed"
Sleep 600ms
Enter

Type 'curl -s "https://threat-intel-api-production.up.railway.app/api/v1/sectors/finance/feed.rss?min_score=70" | head -16'
Enter
Sleep 4500ms

# ---- Scene 3: auditable score breakdown ------------------------------------
Type "# 3) Why did this CVE score what it did?"
Sleep 600ms
Enter

Type 'curl -s https://threat-intel-api-production.up.railway.app/api/v1/sectors/finance/dashboard \'
Enter
Type "  | jq '.top_24h[0].score_breakdown'"
Enter
Sleep 5000ms
