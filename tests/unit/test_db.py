import pytest
from sqlalchemy import text

from threat_intel.core.db import build_engine, session_factory


@pytest.mark.asyncio
async def test_engine_executes_simple_query():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    factory = session_factory(engine)
    async with factory() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar_one() == 1
    await engine.dispose()
