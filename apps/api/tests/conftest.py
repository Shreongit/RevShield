import pytest
from app.core.database import Base, engine

@pytest.fixture(autouse=True, scope="session")
def setup_test_database():
    import asyncio
    async def init_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    asyncio.run(init_tables())
