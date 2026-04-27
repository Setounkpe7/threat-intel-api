from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def build_engine(database_url: str) -> AsyncEngine:
    """Create the async SQLAlchemy engine.

    `pool_pre_ping` is on so we recover gracefully from killed connections —
    relevant when running behind a connection-pooled Postgres.
    """
    return create_async_engine(database_url, pool_pre_ping=True, future=True)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a session, rolls back on exception."""
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
