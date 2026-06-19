from threat_intel.collectors._extract import (
    extract_cves,
    extract_ghsa,
    extract_iocs,
    stable_external_id,
)


def test_extract_cves_basic_and_dedup():
    text = "Affects CVE-2021-44228 and cve-2021-44228 plus CVE-2024-3094."
    assert extract_cves(text) == ["CVE-2021-44228", "CVE-2024-3094"]


def test_extract_cves_ignores_garbage():
    assert extract_cves("version 2021-4 and CVE-XXXX-1") == []


def test_extract_ghsa():
    assert extract_ghsa("see GHSA-jfh8-c2jp-5v3q here") == ["ghsa-jfh8-c2jp-5v3q"]


def test_extract_iocs_refangs_and_validates():
    text = "C2 at hxxp://evil[.]example[.]com/path and ip 10.0.0.1 and 8.8.8.8"
    iocs = extract_iocs(text)
    assert ("url", "http://evil.example.com/path") in iocs
    # private IP must be dropped
    assert ("ip", "10.0.0.1") not in iocs
    assert ("ip", "8.8.8.8") in iocs


def test_extract_iocs_hashes():
    sha256 = "a" * 64
    md5 = "b" * 32
    iocs = extract_iocs(f"hash {sha256} and {md5}")
    assert ("sha256", sha256) in iocs
    assert ("md5", md5) in iocs


def test_extract_iocs_capped():
    text = " ".join(f"{i}.{i}.{i}.{i}" for i in range(1, 60))  # many invalid/garbage
    assert len(extract_iocs(text, max_each=5)) <= 5 * 6  # 6 types max


def test_stable_external_id_prefers_guid():
    assert (
        stable_external_id(
            guid="urn:guid:abc", link="https://x/y", source_name="s", title="t", published="p"
        )
        == "urn:guid:abc"
    )


def test_stable_external_id_hashes_link_when_no_guid():
    eid = stable_external_id(
        guid=None, link="https://x/y", source_name="s", title="t", published="p"
    )
    assert eid.startswith("link:") and len(eid) <= 128


def test_stable_external_id_falls_back_to_composite():
    eid = stable_external_id(guid=None, link=None, source_name="s", title="t", published="p")
    assert eid.startswith("h:") and len(eid) <= 128
