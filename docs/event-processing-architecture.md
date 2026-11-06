# Kuyebiko — Event Processing Architecture (Phase 3)

## 1. Overview

The Event Processing subsystem acts as an asynchronous decoupling buffer and normalization pipeline between Phase 2 filesystem watchers (producers) and the future Phase 4 ransomware detection engine (consumers).

It ensures that native filesystem notification threads (such as `ReadDirectoryChangesW` workers) never block on expensive file inspection, normalization, or detection heuristics.

---

## 2. Target Data Flow Architecture

```
[ NTFS / Win32 Filesystem Mutation ]
                │
                ▼
  [ WindowsDirectoryWatcher ] (Worker Threads)
                │
                │ RawFileNotification
                ▼
   [ EventIngestor (Interface) ]
      - Validates object type
      - Checks pipeline state
      - Tracks ingestion counters
                │
                ▼
   [ BoundedEventQueue ] (Thread-Safe Buffer)
      - Standard library queue.Queue
      - Configurable capacity (KUYEBIKO_EVENT_QUEUE_SIZE)
      - Non-blocking submission
      - Degradation & overflow accounting
                │
                ▼
   [ EventProcessingWorker ] (Single Dedicated Background Thread)
      - Consumes RawFileNotification
      - Predictable sequential ordering
      - Graceful lifecycle management
                │
                ▼
   [ EventNormalizer + RenameCorrelator ] (Reused Phase 2 Core)
      - Correlates two-part renames
      - Assigns monotonic sequences
      - Generates validated FileEvent
                │
                ▼
   [ EventConsumer (Protocol) ]
      - CallbackEventConsumer / InMemoryEventConsumer
      - Future Phase 4 Detection Engine
```

---

## 3. Key Design Decisions

1. **Single Processing Worker:**
   - **Predictable Sequential Ordering:** Single worker ensures strict FIFO processing order per monitored root.
   - **Thread Safety:** Eliminates race conditions in the stateful `RenameCorrelator` and sequence numbering without complex fine-grained locking.
   - **Low Overhead:** Ideal for a local-first desktop endpoint agent.

2. **Decoupled Producers:**
   - Watcher callbacks return immediately after submitting notifications to `BoundedEventQueue`.
   - Never block watcher threads on disk I/O, database persistence, or CPU-intensive analysis.

3. **Explicit Degradation vs. Silent Drops:**
   - Queue overflows are explicitly reported as `IngestionOutcome.QUEUE_FULL`.
   - Overflow metrics and telemetry degradation states are recorded.
   - Queue overflows indicate high I/O burst pressure, not malicious ransomware behaviour.

4. **Extensible Consumer Protocol:**
   - Downstream consumers implement `EventConsumer.handle_event(event: FileEvent)`.
   - Allows drop-in replacement by testing fixtures, logging observers, or the Phase 4 detection pipeline.
