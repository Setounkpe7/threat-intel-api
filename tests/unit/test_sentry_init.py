from threat_intel.core.config import Settings
from threat_intel.main import _init_sentry


def _make_settings(monkeypatch, **overrides) -> Settings:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    for k, v in overrides.items():
        monkeypatch.setenv(k, v)
    return Settings()


def test_init_sentry_noop_when_dsn_blank(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    settings = _make_settings(monkeypatch)
    # Should not raise. The function returns silently before importing sentry_sdk.
    _init_sentry(settings)


def test_init_sentry_calls_sdk_when_dsn_set(monkeypatch):
    settings = _make_settings(monkeypatch, SENTRY_DSN="https://abc@sentry.io/1")

    captured: dict = {}

    def fake_init(**kwargs) -> None:
        captured.update(kwargs)

    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", fake_init)
    _init_sentry(settings)

    assert captured["dsn"] == "https://abc@sentry.io/1"
    assert captured["environment"] == "prod"
    assert captured["traces_sample_rate"] == 0.0
    assert captured["send_default_pii"] is False


def test_init_sentry_passes_release_tag(monkeypatch):
    settings = _make_settings(monkeypatch, SENTRY_DSN="https://abc@sentry.io/1")
    captured: dict = {}
    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: captured.update(kw))
    _init_sentry(settings)

    from threat_intel import __version__

    assert captured["release"] == __version__


def test_init_sentry_uses_environment_from_settings(monkeypatch):
    settings = _make_settings(
        monkeypatch,
        SENTRY_DSN="https://abc@sentry.io/1",
        SENTRY_ENVIRONMENT="staging",
    )
    captured: dict = {}
    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: captured.update(kw))
    _init_sentry(settings)

    assert captured["environment"] == "staging"
