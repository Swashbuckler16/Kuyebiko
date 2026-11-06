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
      - Degradation & application overflow accounting
                │
                ▼
   [ EventProcessingWorker ] (Single Dedicated Background Thread)
      - Consumes RawFileNotification
      - EventOrderingTracker (tracks chronology, latency, out-of-order)
      - EventDeduplicator (conservative filter: never suppresses successive writes)
      - Graceful lifecycle management with bounded consumer retry
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

3. **Explicit Degradation & Separate Overflow Accounting:**
   - Separate metrics: Windows kernel buffer drops (`ERROR_NOTIFY_ENUM_DIR` / 1022) vs. Kuyebiko application queue overflow (`QUEUE_FULL`).
   - Overflow metrics and telemetry degradation states are recorded.
   - Queue overflows indicate high I/O burst pressure, not malicious ransomware behaviour.

4. **Conservative Deduplication:**
   - Only exact duplicate notifications (same root, path, action, and identical monotonic timestamp) are filtered.
   - Legitimate repeated modifications, multi-chunk writes, and create-modify sequences are never suppressed.

5. **Chronology & Out-of-Order Tracking:**
   - Original observation timestamps (`observed_at`, `monotonic_ns`) are strictly preserved.
   - Multi-root streams are monitored independently for out-of-order occurrences without artificial re-sorting buffers.

6. **Error Isolation & Bounded Retries:**
   - Normalization and malformed notification errors do not terminate the worker thread.
   - Downstream consumer delivery failures use bounded immediate retries (`max_consumer_retries`) and record permanently failed events.

