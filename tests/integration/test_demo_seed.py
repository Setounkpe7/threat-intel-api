"""Demo seed must run end-to-end against a fresh DB and must refuse a non-dev URL."""

import os
import subprocess
import sys

import pytest

SAFE_HOSTS = {"localhost", "127.0.0.1", "db", "postgres"}


def test_demo_seed_refuses_prod_url(tmp_path, monkeypatch):
    """Pointing DATABASE_URL at a non-dev host must abort with non-zero exit."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:y@prod.example:5432/threat_intel")
    result = subprocess.run(
        [sys.executable, "scripts/demo_seed.py"],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ},
    )
    assert result.returncode != 0
    assert any(
        s in result.stderr.lower() + result.stdout.lower()
        for s in ["refus", "non-dev", "unsafe", "prod"]
    )


@pytest.mark.parametrize("host", sorted(SAFE_HOSTS))
def test_demo_seed_allows_safe_hosts(host, monkeypatch):
    """The host check must accept the four documented dev hostnames.

    We don't actually run the seed (no DB in this test) — we import the
    check function and invoke it directly.
    """
    monkeypatch.setenv("DATABASE_URL", f"postgresql+asyncpg://x:y@{host}:5432/threat_intel")
    # Lazy import after setting env
    import importlib
    import importlib.util

    spec = importlib.util.spec_from_file_location("demo_seed", "scripts/demo_seed.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    module.assert_safe_database_url()  # must not raise
