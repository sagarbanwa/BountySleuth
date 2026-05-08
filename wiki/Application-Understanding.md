fi
# Application Understanding — BountySleuth

## 1. What this application is
**BountySleuth** is a **browser security analyzer extension** (Chrome + Firefox). It scans the currently visited web page to surface likely bug-bounty-relevant issues across:
- **Network response headers** (WAF fingerprinting, security headers, CORS, cache security)
- **DOM-based weaknesses** (CSRF token presence/quality, heuristic XSS/vector discovery, DOM sink risk patterns)
- **Client-side behavior** (XHR/fetch API interception → generated cURL commands)
- **Sensitive data exposures** (regex-based secret/token extraction)
- **Cloud asset discovery** (S3/Azure/GCP URL patterns)
- **Source map discovery + unpacking** (reconstructs `src_unpacked/` into ZIP)
- **Supply chain** (extract npm packages from sourcemaps and check npm registry for takeover risks)
- **UI reporting + export** (popup renders findings; “Export MD/JSON” copies a report)

## 2. High-level architecture
BountySleuth uses three main execution contexts:

### 2.1 Background script (`background.js`)
**Role:** network-level inspection and cross-page coordination.

**Primary responsibilities:**
- Intercept responses using `chrome.webRequest.onHeadersReceived`.
- Fingerprint:
  - **WAF** via known response headers (e.g., Cloudflare/Akamai/Sucuri signatures)
  - **Security headers** presence/absence (CSP, HSTS, X-Frame-Options, etc.)
  - **CORS** misconfiguration (e.g., `Access-Control-Allow-Origin: *` with credentials)
  - **Cache security issues** (Cache-Control/private/no-store/must-revalidate, s-maxage, Vary problems, Age/ETag hints)
  - **Web Cache Deception** heuristics (URL structure + cacheability gating)
- Maintain **per-host storage**:
  - stores findings under `chrome.storage.local[hostname]`
- Maintain extension badge state based on counts.
- Handle sourcemap unpacking + downloads:
  - fetches `.map` files (with multiple strategies and chunking)
  - builds a dependency-free ZIP (stored format)
  - downloads reconstructed source as:
    - `BountySleuth_Unpacked/<base>_source_code.zip`
- Handle NPM analysis requests:
  - queries npm registry and returns results for popup rendering.

### 2.2 Content script (`content.js`)
**Role:** DOM and JS/HTML scanning plus injection of API interception hooks.

**Lifecycle:**
- Injects immediately at `document_start`.
- Runs the full scan after DOM readiness (waits for `DOMContentLoaded`).

**Primary responsibilities:**
1) **Inject XHR + fetch hook into the page**
   - Wraps `XMLHttpRequest.open/setRequestHeader/send`
   - Wraps `window.fetch`
   - Posts messages with intercepted request data:
     - `method`, `url`, and generated `curl` command
   - Deduplicates intercepted requests and persists them (debounced) to `chrome.storage.local` under `live_apis`.

2) **Run DOM scanners (`scanPage()`)** and populate a findings object.
   - CSRF analysis
   - XSS / HTMLi heuristic analysis
   - DOM sink + “JS protections” detection
   - Cookie security analysis (via `document.cookie`, not HttpOnly)
   - Reflected parameter detection
   - postMessage listener heuristic detection
   - Sensitive data leak scan (HTML + selected same-origin scripts)
   - Cloud asset discovery
   - Endpoint mining
   - Source map discovery
   - SRI misconfiguration scan
   - Host header injection indicators

3) **Support sourcemap content fetching for unpacking**
   - Handles messages from background:
     - `fetchSourceMap`
     - `fetchSourceMapChunk` (Range request when supported)

### 2.3 Popup (`popup.html` + `popup.js`)
**Role:** visualization and export.

**Responsibilities:**
- On open, reads data for the active tab’s `hostname` from storage.
- If no data exists or `Rescan` is clicked:
  - sends `{ action: 'rescan' }` to content script
  - polls storage for results
- Renders findings into multiple collapsible sections.
- Supports:
  - Export Markdown (generates a report string and copies to clipboard)
  - Export JSON (copies the storage object as JSON)
- Triggers:
  - NPM analysis by sending `{ action: 'checkNpmPackages' }` to background
  - Sourcemap unpacking by sending `{ action: 'unpackSourceMap' }` to background

## 3. Storage model (per-host)
All findings are saved keyed by **hostname**:

### 3.1 Header/network findings (background)
Stored under `chrome.storage.local[hostname]` with fields like:
- `wafs: string[]`
- `security_headers_missing: {name, severity}[]`
- `security_headers_present: {name, value, severity}[]`
- `server_info: string[]` (technology and fingerprint headers)
- `cors: { origin, credentials, severity, issue, endpoint } | null`
- `cache_issues: { url, type, severity, verdict, header?, cacheEvidence?, recommendation? }[]`

### 3.2 DOM findings (content script)
Stored under the same hostname object, overwritten for most “page scan” fields:
- `csrf: object[]`
- `xss: object[]` (heuristic input vector findings)
- `dom_sinks: object[]`
- `cookies: object[]`
- `reflected_params: object[]`
- `post_messages: object[]`
- `leaks: object[]`
- `cloud_assets: object[]`
- `endpoints: string[]`
- `js_files: string[]`
- `js_protections: string[]`

### 3.3 Sourcemap and supply-chain findings
- `sourcemaps: object[]`
  - each entry contains `jsUrl`, `mapUrl`, accessibility status, and optional `analysis` (framework, source count, packages, etc.)
- `sri_issues: object[]`
- `npm_analysis: object[]` (registry check results returned by background)

### 3.4 Host header injection indicators
- `host_header: object[]`

### 3.5 Live API capture
- `live_apis: { method, url, curl }[]`

## 4. Module-by-module understanding

## 4.1 WAF & server fingerprint (background)
**Input:** response headers from `webRequest.onHeadersReceived`.
**Logic:**
- Detects WAF via known header name/value signatures.
- Detects server tech via `server` header substring matches.
**Output:**
- `wafs` array
- `server_info` list

## 4.2 Security headers check (background)
**Input:** response headers.
**Logic:**
- For main frame only (`details.type === 'main_frame'`), checks presence of configured security headers.
**Output:**
- `security_headers_missing`, `security_headers_present`

## 4.3 CORS analysis (background)
**Input:** response headers.
**Logic:**
- Extracts `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.
- Flags:
  - wildcard `*` + credentials → **CRITICAL**
  - wildcard `*` alone → **MEDIUM**
  - non-wildcard + credentials → **HIGH**
**Output:**
- `cors` object (latest) + `cors_history` entries when present.

## 4.4 Cache security analysis + cache deception (background)
**Input:** response headers + URL + status code.
**Logic:**
- Reduces false positives by:
  - gating on status code (ignores 4xx/5xx)
  - gating on explicit non-cacheable directives (`no-store`, `private`, etc.)
  - gating on CDN bypass hints (`cf-cache-status bypass/dynamic`, `x-cache` misses with no-store/private)
  - content-type mismatch heuristic to avoid HTML error pages being interpreted as cacheable assets.
- Checks:
  - public caching of sensitive endpoints
  - missing `no-store` on sensitive URLs
  - long max-age / s-maxage on sensitive routes
  - missing `Vary: Authorization, Cookie`-like hints
  - Age, ETag/Last-Modified conditional caching hints
  - unkeyed header poisoning risk (dangerous proxy headers not present in `Vary`)
  - “Web Cache Deception” path confusion patterns + cache evidence (hit/age/etag)
**Output:**
- `cache_issues[]`

## 4.5 Live API Collector (content script injection)
**Input:** runtime XHR/fetch calls from the page.
**Logic:**
- Generates curl commands including headers and body.
- Filters obvious static resources.
- Deduplicates based on `curl` string.
- Debounces storage updates to avoid excessive writes.
**Output:**
- `live_apis[]`

## 4.6 CSRF analysis (content script)
**Input:** DOM forms + hidden inputs + meta tags + inline script patterns.
**Logic (high level):**
- Detects presence of anti-CSRF tokens via:
  - hidden inputs (by token-like name/id)
  - global meta tokens (csrf/xsrf)
  - inline JS token patterns
  - form attributes containing token-like names
- Flags sensitive action forms missing tokens → HIGH/CRITICAL.
- If tokens found, runs heuristic “weak token” checks:
  - too short
  - low entropy / predictable patterns
  - timestamp-like tokens
  - JWT-like tokens
  - duplicate/static tokens across multiple forms
- Additional heuristics:
  - GET used for sensitive actions
  - missing clickjacking defenses
  - formaction override buttons
  - token in URL (referer leakage risk)
**Output:**
- `csrf[]` entries

## 4.7 XSS / HTMLi heuristic analysis (content script)
**Input:** URL query params + DOM inputs/values.
**Logic:**
- Looks at input fields’ constraints (`maxlength`, `pattern`).
- Checks whether param names match input names and whether values appear reflected in DOM.
- Classifies severity as UI states (GREEN/YELLOW/RED) based on “protection level” assumptions.
- Highlights flagged fields visually.
**Output:**
- `xss[]`

## 4.8 DOM sinks + JS protections (content script)
**Input:** inline scripts (text content).
**Logic:**
- Scans for dangerous sink patterns (innerHTML/eval/document.write/etc.)
- Heuristically decides if user-controllable sources are present.
- Detects sanitizers (DOMPurify, js-xss, sanitize-html) and simple custom replace-filter patterns.
**Output:**
- `dom_sinks[]`
- `js_protections[]`

## 4.9 Cookies (content script)
**Input:** `document.cookie`.
**Logic:**
- Since HttpOnly cookies are not readable, results are explicitly “JS-accessible only”.
- Flags session-like cookie names and HTTP (non-HTTPS) transport risks.
**Output:**
- `cookies[]`

## 4.10 Reflected parameter detection (content script)
**Input:** `window.location.search` and `window.location.hash` params + DOM HTML/body text.
**Logic:**
- Finds param values present in `document.body.innerHTML`.
- Attempts to classify reflection context: script blocks, attributes, URL attributes, text.
- Heuristically upgrades severity based on presence of special characters in reflected values.
**Output:**
- `reflected_params[]`

## 4.11 postMessage listener detection (content script)
**Input:** inline script text.
**Logic:**
- Scans for `addEventListener` + `message`.
- Flags missing origin validation patterns.
**Output:**
- `post_messages[]`

## 4.12 Sensitive data leak scan (content script)
**Input:** page HTML + up to a capped set of same-origin scripts.
**Logic:**
- Runs regex extraction against a large set of known secret patterns (AWS/GCP/Azure/Stripe/GitHub/tokens/private keys/etc.).
- Deduplicates matches.
- Uses network timeouts/AbortController for script fetches.
**Output:**
- `leaks[]`

## 4.13 Cloud infrastructure detection (content script)
**Input:** page HTML.
**Logic:**
- Regex patterns for storage URLs and signed URLs.
**Output:**
- `cloud_assets[]`

## 4.14 Endpoint mining (content script)
**Input:** DOM attributes + quoted strings in HTML.
**Logic:**
- Extracts `href/src/action` values.
- Separates likely JS files vs other endpoints by extension regex.
- Also finds quoted `/path`-like strings.
**Output:**
- `endpoints[]`
- `js_files[]`

## 4.15 Source map detector & sourcemap unpacking support (content + background)
**Input:** DOM scanning for `sourceMappingURL` + `.map` probing.
**Logic in content.js:**
- Finds `//# sourceMappingURL=` in JS and `/*# sourceMappingURL=` in CSS.
- Probes common `.map` candidates and certain build-tool patterns.
- For accessible maps, it validates and may fetch map content for framework/package analysis.
**Logic in background.js:**
- For unpacking, fetches the sourcemap JSON.
- Requires embedded `sourcesContent` to reconstruct sources.
- Writes:
  - `src_unpacked/<normalized_source_path>` files
  - includes the original `.map` itself under `src_unpacked/`
- Extracts npm packages by scanning `sources` paths for `node_modules/<pkg>` segments.
**Output:**
- `sourcemaps[]` entries
- Unpack downloads ZIP
- Extracted package list returned to popup for NPM analysis

## 4.16 NPM package analyzer (background + popup)
**Input:** list of packages extracted from sourcemap analysis.
**Logic:**
- Queries npm registry for each package name.
- If package doesn’t exist (404), flags takeover risk.
  - Unscoped names → CRITICAL-style flag in current implementation.
**Output:**
- `npm_analysis[]` with severity, verdict, and URLs.

## 4.17 Subresource Integrity (SRI) scanner (content script)
**Input:** DOM `script`/`link` tags + importmap + iframes + worker/service worker patterns.
**Logic:**
- Flags 3rd-party resources lacking `integrity`.
- Flags weak integrity hashes (SHA-256 patterns) vs stronger ones.
- Flags suspicious patterns:
  - `crossorigin` without `integrity`
  - modulepreload/preload without integrity
  - 3rd-party iframes without sandbox
  - dynamic external script loading patterns
  - importmaps pointing to 3rd-party origins
  - CSS `@import` of external URLs
**Output:**
- `sri_issues[]`

## 4.18 Host header injection indicators (content script)
**Input:** DOM markers + inline JS patterns.
**Logic:**
- Looks for canonical/OG URLs with hostname.
- Checks `base href` and password reset / login / email form indicators.
- Provides reference payload headers.
**Output:**
- `host_header[]`

## 5. Operational lifecycle (end-to-end)
1) User navigates to a page.
2) **Content script** injects API hooks and later runs `scanPage()` to populate DOM findings.
3) **Background service worker** concurrently inspects network responses and fills header-based findings.
4) Results are persisted per hostname in `chrome.storage.local`.
5) User opens popup:
   - popup reads stored data and renders modules.
6) User clicks “Unpack ZIP” for accessible sourcemaps:
   - popup requests background to unpack.
   - background downloads ZIP and returns extracted package info (when possible).
   - popup can auto-trigger NPM analysis using returned packages.
7) User exports report (Markdown/JSON) for bug bounty documentation.

## 6. Notes on heuristics & limitations
- Many modules are **heuristic/regex-based** (not guaranteed true positive).
- Cookies scanned via `document.cookie` are **not HttpOnly** cookies.
- Source map unpacking depends on the presence of `sourcesContent` within `.map` files.
- Leak scanning is regex-based and may produce false positives.

---

This document summarizes the architecture and the module outputs as they exist in the current codebase (Chrome/Firefox `background.js` + `content.js`, and `popup.js`).

