# Kuyebiko — Duplicate Event Policy

## 1. Overview

Windows `ReadDirectoryChangesW` and filesystem APIs frequently emit closely spaced notifications. However, in ransomware detection, **repeated write operations are vital behavioral indicators** (e.g., chunked file encryption, multi-pass overwrites, and rapid attribute tampering).

Kuyebiko adheres to a strict **conservative deduplication policy**: it suppresses only provably identical notification duplicates while rigorously preserving legitimate sequential modifications.

---

## 2. What Qualifies as a Duplicate

A notification is classified as a duplicate **only** if all of the following match an entry currently in the bounded fingerprint cache:
1. `root_id`: Same monitored directory root.
2. `relative_path`: Exact same normalized relative path.
3. `action`: Same `WindowsFileAction` code.
4. `is_directory`: Same directory attribution.
5. `monotonic_ns`: **Exact identical observation monotonic timestamp**.

---

## 3. False Positive Prevention (What is NEVER Suppressed)

Kuyebiko guarantees that the following valid sequences are **never** suppressed:
1. **Creation followed by Modification:** `ADDED` followed by `MODIFIED` on the same file path is fully preserved.
2. **Successive Modifications:** Two `MODIFIED` actions with distinct observation timestamps (`monotonic_ns`) represent separate writes or metadata flushes and are **always preserved**.
3. **Rename followed by Modification:** Renaming a file and immediately modifying its contents produces distinct, unsuppressed events.
4. **Distinct Roots:** Identical file paths under different `root_id` identifiers are isolated and never cross-deduplicated.
5. **Successive Deletions:** Distinct removals are never conflated.

---

## 4. Cache Bounding and Memory Limits

- The fingerprint cache uses a bounded `OrderedDict` (default capacity `1,000` entries).
- When capacity is reached, the oldest fingerprint is evicted (`FIFO` policy), incrementing `cache_evictions`.
- Memory is strictly $O(1)$ with respect to total processed events.
