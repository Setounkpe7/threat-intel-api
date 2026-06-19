import asyncio

import httpx
import typer
from sqlalchemy import select

from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import get_settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.core.logging import configure_logging
from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService

app = typer.Typer(help="One-shot operations for the threat-intel-api.", no_args_is_help=True)


@app.callback()
def _root() -> None:
    """One-shot ingestion operations."""


@app.command()
def nvd() -> None:
    """Run a single NVD collection cycle synchronously (useful for demos)."""
    settings = get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    async def _run() -> None:
        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        async with factory() as s:
            existing = (
                await s.execute(select(Source).where(Source.name == "nvd"))
            ).scalar_one_or_none()
            if existing is None:
                s.add(
                    Source(
                        name="nvd",
                        kind=SourceKind.cve_feed,
                        url=settings.nvd_base_url,
                        enabled=True,
                    )
                )
                await s.commit()

        async with httpx.AsyncClient(timeout=30.0) as http:
            collector = NVDCollector(http_client=http, settings=settings)
            service = IngestionService(session_factory=factory, collectors=[collector])
            result = await service.run("nvd")
            typer.echo(
                f"inserted={result.inserted} updated={result.updated} unchanged={result.unchanged}"
            )
        await engine.dispose()

    asyncio.run(_run())


@app.command()
def rss(source_name: str) -> None:
    """Run a single RSS feed collection cycle synchronously."""
    settings = get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    async def _run() -> None:
        from threat_intel.services.rss_feed_loader import RSSFeedLoader

        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        async with httpx.AsyncClient(timeout=30.0) as http:
            collectors = RSSFeedLoader(http, settings, settings.feeds_path).build_collectors()
            match = next((c for c in collectors if c.source_name == source_name), None)
            if match is None:
                typer.echo(f"no RSS feed named {source_name!r} in feeds.yaml")
                raise typer.Exit(code=1)
            async with factory() as s:
                existing = (
                    await s.execute(select(Source).where(Source.name == source_name))
                ).scalar_one_or_none()
                if existing is None:
                    s.add(
                        Source(name=source_name, kind=SourceKind.rss, url=match.url, enabled=True)
                    )
                    await s.commit()
            service = IngestionService(session_factory=factory, collectors=[match])
            result = await service.run(source_name)
            typer.echo(f"inserted={result.inserted} updated={result.updated}")
        await engine.dispose()

    asyncio.run(_run())


if __name__ == "__main__":
    app()
