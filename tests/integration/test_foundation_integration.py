import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import text

from kuyebiko.core.config import KuyebikoSettings
from kuyebiko.models.events import (
    EventSource,
    EventType,
    FileEvent,
    TelemetryQuality,
)
from kuyebiko.models.incidents import (
    IncidentConfidence,
    IncidentSeverity,
    IncidentStatus,
    SecurityIncident,
)
from kuyebiko.models.telemetry import (
    CollectorStatus,
    MonitoringStatus,
    TelemetrySnapshot,
)
from kuyebiko.storage.database import Database
from kuyebiko.utils.logging_config import (
    configure_logging,
    shutdown_logging,
)


def run_async(coroutine):
    """Helper to run coroutines in synchronous test functions."""
    return asyncio.run(coroutine)


def test_configuration_and_database_integration(tmp_path: Path):
    """Scenario A: Verify KuyebikoSettings and Database integration."""

    async def scenario():
        db_path = tmp_path / "integration_kuyebiko.db"
        settings = KuyebikoSettings(
            _env_file=None,
            database_path=db_path,
        )
        database = Database(settings)

        try:
            # Initialize database and verify file creation
            await database.initialize()
            assert database.database_path.exists()
            assert database.database_path.is_file()

            # Verify health check succeeds
            assert await database.health_check() is True

            # Verify integrity check returns "ok"
            integrity = await database.integrity_check()
            assert integrity == "ok"
        finally:
            # Verify clean disposal of database resources
            await database.close()

    run_async(scenario())


def test_database_session_integration(tmp_path: Path):
    """Scenario B: Verify asynchronous SQLAlchemy session execution."""

    async def scenario():
        db_path = tmp_path / "session_kuyebiko.db"
        settings = KuyebikoSettings(
            _env_file=None,
            database_path=db_path,
        )
        database = Database(settings)

        try:
            await database.initialize()

            # Open an async session and execute a query
            async with database.session_factory() as session:
                result = await session.execute(
                    text("SELECT 42 AS answer, 'kuyebiko' AS app")
                )
                row = result.mappings().one()

                assert row["answer"] == 42
                assert row["app"] == "kuyebiko"
        finally:
            await database.close()

    run_async(scenario())


def test_model_instantiation_and_serialization():
    """Scenario C: Verify model instantiation and Pydantic serialization."""
    now = datetime.now(UTC)

    # 1. FileEvent
    event = FileEvent(
        root_id="root-integration-001",
        file_path="src/critical_document.docx",
        event_type=EventType.MODIFIED,
        monotonic_ns=9876543210,
        source=EventSource.WINDOWS_WATCHER,
        sequence_number=1,
        quality=TelemetryQuality.NORMAL,
        timestamp_utc=now,
    )

    event_dict = event.model_dump()
    assert event_dict["root_id"] == "root-integration-001"
    assert event_dict["event_type"] == "modified"
    assert event_dict["quality"] == "normal"

    event_json = event.model_dump_json()
    deserialized_event = json.loads(event_json)
    assert deserialized_event["event_id"] == event.event_id
    assert deserialized_event["file_path"] == "src/critical_document.docx"

    # 2. SecurityIncident
    incident = SecurityIncident(
        root_id="root-integration-001",
        title="Elevated write burst detected",
        description="Rapid modification of diverse files within 5-second window.",
        severity=IncidentSeverity.HIGH,
        confidence=IncidentConfidence.MODERATE,
        risk_score=78,
        status=IncidentStatus.OPEN,
        first_seen=now,
        last_seen=now,
        evidence_event_ids=[event.event_id],
        signal_families=["modification_burst", "file_diversity"],
    )

    incident_dict = incident.model_dump()
    assert incident_dict["severity"] == "high"
    assert incident_dict["risk_score"] == 78
    assert incident_dict["evidence_event_ids"] == [event.event_id]

    incident_json = incident.model_dump_json()
    deserialized_incident = json.loads(incident_json)
    assert deserialized_incident["incident_id"] == incident.incident_id
    assert deserialized_incident["status"] == "open"

    # 3. TelemetrySnapshot
    snapshot = TelemetrySnapshot(
        collector_id="collector-main",
        root_id="root-integration-001",
        monitoring_status=MonitoringStatus.RUNNING,
        collector_status=CollectorStatus.ACTIVE,
        events_received=500,
        events_dropped=0,
        queue_capacity=10000,
        queue_depth=12,
        collection_errors=0,
        last_heartbeat=now,
        last_event_at=now,
        observed_at=now,
        degradation_reasons=[],
    )

    snapshot_dict = snapshot.model_dump()
    assert snapshot_dict["monitoring_status"] == "running"
    assert snapshot_dict["events_received"] == 500

    snapshot_json = snapshot.model_dump_json()
    deserialized_snapshot = json.loads(snapshot_json)
    assert deserialized_snapshot["snapshot_id"] == snapshot.snapshot_id
    assert deserialized_snapshot["queue_depth"] == 12


def test_logging_integration(tmp_path: Path):
    """Scenario D: Verify centralized logging file output and shutdown."""
    log_dir = tmp_path / "integration_logs"

    try:
        logger = configure_logging(log_dir)
        test_message = "Kuyebiko foundation integration log test message"
        logger.info(test_message)

        # Flush all handlers to disk
        for handler in logger.handlers:
            handler.flush()

        log_file = log_dir / "kuyebiko.log"
        assert log_file.exists()
        log_content = log_file.read_text(encoding="utf-8")
        assert test_message in log_content
        assert "INFO" in log_content
        assert "kuyebiko" in log_content
    finally:
        shutdown_logging()


def test_complete_foundation_integration(tmp_path: Path):
    """Scenario E: Complete foundation integration combining components.

    Validates config, db, models, and logging together.
    """

    async def scenario():
        db_path = tmp_path / "complete_foundation.db"
        log_dir = tmp_path / "complete_logs"

        # 1. Configuration
        settings = KuyebikoSettings(
            _env_file=None,
            database_path=db_path,
            log_level="DEBUG",
        )

        # 2. Centralized Logging
        logger = configure_logging(log_dir)
        logger.info("Initializing Kuyebiko foundation integration test")

        # 3. Database initialization
        database = Database(settings)
        try:
            await database.initialize()
            assert await database.health_check() is True
            assert await database.integrity_check() == "ok"
            logger.info("Database initialized successfully at %s", db_path)

            # 4. Model instantiation and serialization
            now = datetime.now(UTC)
            event = FileEvent(
                root_id="monitored-root-prod",
                file_path="reports/financial_2026.xlsx",
                event_type=EventType.MODIFIED,
                monotonic_ns=100020003000,
                source=EventSource.WINDOWS_WATCHER,
                sequence_number=42,
                quality=TelemetryQuality.NORMAL,
                timestamp_utc=now,
            )

            incident = SecurityIncident(
                root_id="monitored-root-prod",
                title="Potential ransomware activity",
                description="Simulated multi-signal correlation alert.",
                severity=IncidentSeverity.MEDIUM,
                confidence=IncidentConfidence.HIGH,
                risk_score=55,
                status=IncidentStatus.OPEN,
                first_seen=now,
                last_seen=now,
                evidence_event_ids=[event.event_id],
                signal_families=["modification_burst"],
            )

            telemetry = TelemetrySnapshot(
                collector_id="watcher-01",
                root_id="monitored-root-prod",
                monitoring_status=MonitoringStatus.RUNNING,
                collector_status=CollectorStatus.ACTIVE,
                events_received=42,
                events_dropped=0,
                queue_capacity=10000,
                queue_depth=1,
                last_heartbeat=now,
            )

            # Ensure models serialize to valid JSON
            event_json = event.model_dump_json()
            incident_json = incident.model_dump_json()
            telemetry_json = telemetry.model_dump_json()

            assert len(json.loads(event_json)["event_id"]) > 0
            assert json.loads(incident_json)["risk_score"] == 55
            assert json.loads(telemetry_json)["monitoring_status"] == "running"

            logger.info(
                "Created incident %s with risk score %d",
                incident.incident_id,
                incident.risk_score,
            )

            # 5. Flush logs and verify contents
            for handler in logger.handlers:
                handler.flush()

            log_file = log_dir / "kuyebiko.log"
            assert log_file.exists()
            content = log_file.read_text(encoding="utf-8")
            assert "Initializing Kuyebiko foundation integration test" in content
            assert incident.incident_id in content

        finally:
            await database.close()
            shutdown_logging()

    run_async(scenario())
