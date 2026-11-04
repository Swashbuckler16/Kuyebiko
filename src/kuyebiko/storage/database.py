from pathlib import Path

from sqlalchemy import URL, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from kuyebiko.core.config import KuyebikoSettings, get_settings


class Database:
    """Manages Kuyebiko's local SQLite database."""

    def __init__(
        self,
        settings: KuyebikoSettings | None = None,
    ) -> None:
        self.settings = settings or get_settings()

        self.database_path = Path(self.settings.database_path).expanduser().resolve()

        # Ensure the database directory exists.
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        database_url = URL.create(
            drivername="sqlite+aiosqlite",
            database=str(self.database_path),
        )

        self.engine: AsyncEngine = create_async_engine(
            database_url,
            connect_args={"timeout": 30},
            echo=self.settings.debug,
        )

        self._configure_sqlite()

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    def _configure_sqlite(self) -> None:
        """Configure SQLite whenever a connection is opened."""

        @event.listens_for(self.engine.sync_engine, "connect")
        def set_sqlite_pragmas(
            dbapi_connection,
            connection_record,
        ) -> None:
            cursor = dbapi_connection.cursor()

            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

    async def initialize(self) -> None:
        """Create the database file and verify connectivity."""

        async with self.engine.begin() as connection:
            result = await connection.execute(text("SELECT 1"))

            if result.scalar_one() != 1:
                raise RuntimeError("Database initialization failed")

    async def health_check(self) -> bool:
        """Return True if the database is accessible."""

        try:
            async with self.engine.connect() as connection:
                result = await connection.execute(text("SELECT 1"))
                return result.scalar_one() == 1

        except SQLAlchemyError:
            return False

    async def integrity_check(self) -> str:
        """Run SQLite's built-in database integrity check."""

        async with self.engine.connect() as connection:
            result = await connection.execute(text("PRAGMA integrity_check"))

            return str(result.scalar_one())

    async def close(self) -> None:
        """Dispose of database connections."""

        await self.engine.dispose()
