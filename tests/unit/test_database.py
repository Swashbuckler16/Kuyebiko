import asyncio

from sqlalchemy.exc import OperationalError

from kuyebiko.core.config import KuyebikoSettings
from kuyebiko.storage.database import Database


def run_async(coroutine):
    return asyncio.run(coroutine)


def create_test_database(tmp_path):
    settings = KuyebikoSettings(
        _env_file=None,
        database_path=tmp_path / "test_kuyebiko.db",
    )

    return Database(settings)


def test_database_initialization(tmp_path):
    async def scenario():
        database = create_test_database(tmp_path)

        try:
            await database.initialize()

            assert database.database_path.exists()
        finally:
            await database.close()

    run_async(scenario())


def test_database_health_check(tmp_path):
    async def scenario():
        database = create_test_database(tmp_path)

        try:
            await database.initialize()

            assert await database.health_check() is True
        finally:
            await database.close()

    run_async(scenario())


def test_database_health_check_failure(tmp_path, monkeypatch):
    async def scenario():
        database = create_test_database(tmp_path)

        class FaultyEngine:
            def connect(self):
                raise OperationalError("Simulated failure", {}, None)

        monkeypatch.setattr(database, "engine", FaultyEngine())

        assert await database.health_check() is False

    run_async(scenario())


def test_database_integrity_check(tmp_path):
    async def scenario():
        database = create_test_database(tmp_path)

        try:
            await database.initialize()

            result = await database.integrity_check()

            assert result == "ok"
        finally:
            await database.close()

    run_async(scenario())


def test_database_directory_created_automatically(tmp_path):
    async def scenario():
        nested_path = tmp_path / "nested" / "database" / "test.db"

        settings = KuyebikoSettings(
            _env_file=None,
            database_path=nested_path,
        )

        database = Database(settings)

        try:
            await database.initialize()

            assert nested_path.exists()
            assert nested_path.parent.exists()
        finally:
            await database.close()

    run_async(scenario())


def test_database_session_factory(tmp_path):
    async def scenario():
        database = create_test_database(tmp_path)

        try:
            await database.initialize()

            async with database.session_factory() as session:
                from sqlalchemy import text

                result = await session.execute(text("SELECT 1"))

                assert result.scalar_one() == 1
        finally:
            await database.close()

    run_async(scenario())
