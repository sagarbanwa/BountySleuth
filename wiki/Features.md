# Features

BountySleuth performs real-time analysis across multiple attack vectors:

* **📡 WAF & Server Fingerprint**: Detects Web Application Firewalls (Cloudflare, Akamai, Sucuri, AWS, etc.) and server technologies.
* **🔒 Security Headers**: Analyzes headers for misconfigurations (missing CSP, HSTS, X-Frame-Options, etc.).
* **🌐 CORS Misconfiguration**: Checks for wildcard origins and credentials allowed, identifying potential cross-origin data leaks.
* **💉 Host Header Injection**: Automatically analyzes requests for Host Header vulnerabilities by injecting common payloads and monitoring responses.
* **🛡️ CSRF Analysis**: Detects forms without proper CSRF protection, analyzing tokens in hidden inputs, meta tags, and global variables. Includes weak token detection and static token analysis.
* **💉 XSS / HTMLi Analysis**: Evaluates and highlights input fields based on constraints (maxlength, patterns) and detects real-time reflections in the DOM.
* **⚡ DOM Sinks**: Scans inline scripts for dangerous sinks (`innerHTML`, `eval`, `document.write`) interacting with user-controllable sources.
* **🔄 Reflected Parameters**: Automatically catches parameters reflected in the HTML body, scripts, or attributes and assesses severity.
* **📩 PostMessage Listeners**: Inspects `postMessage` event listeners for insecure origins or dangerous handlers.
* **🔓 Sensitive Data Leaks**: Extracts over 40 types of exposed secrets, tokens, API keys (AWS, GCP, Azure, Stripe, GitHub, etc.), and private keys from the page source.
* **☁️ Cloud Infrastructure**: Identifies cloud assets, storage buckets (S3, Azure Blob, GCP Storage), and signed URLs exposed in the application.
* **📡 Live API Collector (cURL)**: Intercepts background XHR and Fetch requests, automatically generating ready-to-use cURL commands for deeper API testing.
* **🗺️ Endpoint Map / JS**: Automatically maps discovered API routes and JavaScript files for easy extraction.
* **🗺️ Source Map Detector & Unpacker**: Discovers exposed JavaScript/CSS source maps (`.map` files), validates accessibility, analyzes frameworks, and enables **one-click ZIP download** of fully reconstructed original source code (`src_unpacked/`).
* **📦 NPM Package Analyzer**: Extracts npm packages from source maps and checks against the npm registry for **Dependency Confusion / Private Package Takeover** vulnerabilities. Flags unscoped private packages as CRITICAL takeover targets.
* **💾 Cache Security**: Comprehensive cache header analysis with 14+ security checks including:
  - **Web Cache Deception** (6 attack patterns): basic extension, delimiter-based (`~;:#!@`), encoded path (`%2e%2e`), double path (`/account.php/poc.css`), query param trick, wildcard suffix
  - Cache Poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL, X-Forwarded-Path, etc.)
  - X-Cache HIT on sensitive endpoints
  - Public caching on sensitive endpoints
  - Missing no-store/must-revalidate directives
  - CDN misconfiguration detection
* **🔗 Subresource Integrity (SRI)**: Supply chain security scanner detecting:
  - 3rd party CDN scripts without integrity hashes
  - ES Modules without SRI
  - Dynamic script loading patterns
  - Service Workers/Web Workers from external sources
  - Import maps pointing to 3rd party
  - Iframes without sandbox restrictions
  - CSS @import from external sources
* **🍪 Cookie Security**: Flags insecure session cookies (e.g., missing HttpOnly or Secure flags).
