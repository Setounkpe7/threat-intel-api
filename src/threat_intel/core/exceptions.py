class ThreatIntelException(Exception):
    """Base class for all domain exceptions."""


class ConfigurationError(ThreatIntelException):
    """Invalid or missing configuration at boot."""


class CollectorError(ThreatIntelException):
    """Base class for collector failures."""


class CollectorHTTPError(CollectorError):
    def __init__(self, *, status_code: int, url: str, message: str = "") -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} on {url}: {message}".rstrip(": "))


class CollectorParseError(CollectorError):
    """Source returned a payload we cannot parse."""


class PersistenceError(ThreatIntelException):
    """Database error during ingestion or query."""


class ThreatNotFoundException(ThreatIntelException):
    def __init__(self, *, cve_id: str) -> None:
        self.cve_id = cve_id
        super().__init__(f"Threat not found for {cve_id}")
