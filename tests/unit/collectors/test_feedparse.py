import pytest

from threat_intel.collectors._feedparse import ParsedEntry, assert_safe_xml, parse_feed
from threat_intel.core.exceptions import CollectorParseError

_RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Feed</title>
<item>
  <title>CVE-2021-44228 exploited</title>
  <link>https://example.test/a</link>
  <guid isPermaLink="false">guid-1</guid>
  <description>Log4Shell &lt;b&gt;active&lt;/b&gt;</description>
  <pubDate>Mon, 13 Dec 2021 00:00:00 GMT</pubDate>
  <category>advisory</category>
</item></channel></rss>"""

_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<rss version="2.0"><channel><item><title>&xxe;</title></item></channel></rss>"""

_BILLION = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [ <!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"> ]>
<rss><channel><item><title>&lol2;</title></item></channel></rss>"""


def test_assert_safe_xml_accepts_clean():
    assert_safe_xml(_RSS)  # no raise


def test_assert_safe_xml_rejects_xxe():
    with pytest.raises(CollectorParseError):
        assert_safe_xml(_XXE)


def test_assert_safe_xml_rejects_entity_bomb():
    with pytest.raises(CollectorParseError):
        assert_safe_xml(_BILLION)


def test_parse_feed_maps_fields():
    entries = parse_feed(_RSS)
    assert len(entries) == 1
    e = entries[0]
    assert isinstance(e, ParsedEntry)
    assert e.guid == "guid-1"
    assert e.link == "https://example.test/a"
    assert "CVE-2021-44228" in e.title
    assert "advisory" in e.tags
    assert e.published.startswith("Mon, 13 Dec 2021")
