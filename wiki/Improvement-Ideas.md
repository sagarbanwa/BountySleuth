# Improvement Ideas — BountySleuth

This document lists concrete optimizations and feature additions that would improve correctness, performance, and developer maintainability.

## 1) Add structured evidence + confidence to findings
**Problem:** Many modules use regex/heuristics without a standardized evidence payload.

**Introduce:**
- For every finding type, store:
  - `evidence: []` (examples: header name/value matched, regex used, DOM selector, URL patterns, cache-control directives observed)
  - `confidence: 'low'|'medium'|'high'`
  - `matchedBy: string` (module-specific rule identifier)

**Benefit:** Fewer false positives and faster triage when exporting reports.

## 2) Normalize severity + scoring across modules
**Problem:** XSS uses GREEN/YELLOW/RED; other modules use HIGH/MEDIUM/LOW/CRITICAL.

**Introduce:**
- One severity enum across the whole extension:
  - `critical | high | medium | low | info`
- UI mapping becomes deterministic.

## 3) Standardize dedupe with finding IDs
**Problem:** Dedupe is inconsistent between modules (some dedupe by value, some by URL, others not).

**Introduce:**
- Add a canonical `findingId` per module:
  - `findingId = sha1(module + ':' + hostname + ':' + canonicalTarget)`
- Dedupe by `findingId` for storage merges.

## 4) Performance: sourcemap probing cache (TTL)
**Problem:** Re-probing and re-analyzing sourcemaps on every rescan is expensive.

**Introduce:**
- Cache results of:
  - map URL accessibility (`HEAD` result)
  - map analysis (`framework`, `sourceCount`, `packages`)
- Store with TTL (e.g., 24h) in `chrome.storage.local`.

## 5) Performance: leak scanning two-phase strategy
**Problem:** Leak scan currently runs many regexes over large HTML + fetched scripts.

**Introduce:**
- Phase 1: cheap prefilter (token density / keyword presence) to decide if deep scan is needed.
- Phase 2: full regex sweep only when prefilter triggers.
- Maintain a per-script scan hash to skip previously scanned JS.

## 6) Add user controls for heavy actions
**Introduce UI toggles in popup:]
- “Auto analyze NPM after unpack” (default on/off)
- “Max sourcemaps to probe per page”
- “Max scripts for leak scan”
- “Disable ZIP unpack”

**Benefit:** Avoid accidental long-running scans.

## 7) Export v2 with evidence + schema
**Problem:** Export MD is not fully evidence-driven.

**Introduce:**
- `Export MD v2` that:
  - prints normalized severity
  - includes `evidence` summaries
  - includes consistent sections per module
  - includes a “raw evidence appendix”

## 8) Cross-browser diagnostics
**Introduce:**
- Add a hidden “diagnostics” panel that reports:
  - message passing success rate
  - chunked sourcemap download support
  - storage write latency

## 9) Add a formal findings schema contract
**Introduce new docs:]
- `wiki/Findings-Schema.md`
  - exact shape per module entry
  - canonical field names
  - dedupe keys

## 10) Refactor hotspots (maintainability)
**Possible refactors:**
- Move large scanners into smaller functions per module with unit-testable helpers.
- Extract shared utilities:
  - URL normalization
  - severity mapping
  - evidence extraction helpers

---

## Proposed next concrete documentation step
- Create `wiki/Findings-Schema.md` to define canonical storage + entry shapes.
- Then (optionally) implement one performance optimization (sourcemap TTL cache) behind a feature flag.

