# 🔍 BountySleuth - Web Sec Analyzer

**BountySleuth** is a professional bug bounty companion and universal web security scanner available as a browser extension for both Chrome and Firefox. It passively monitors and actively analyzes web applications for common vulnerabilities, misconfigurations, and sensitive data exposures while you browse.

> **Developed by [Security0x0 Research And Development Private Limited](mailto:contact@secuirty0x0.com)**

|               Dashboard Explorer                |             Analysis & Endpoints              |
| :---------------------------------------------: | :-------------------------------------------: |
| ![BountySleuth Dashboard](assets/dashboard.png) | ![BountySleuth Features](assets/features.png) |

## 🚀 Features

BountySleuth performs real-time analysis across multiple attack vectors:

* **📡 WAF & Server Fingerprint**: Detects Web Application Firewalls (Cloudflare, Akamai, Sucuri, AWS, etc.) and server technologies.
* **🔒 Security Headers**: Analyzes headers for misconfigurations (missing CSP, HSTS, X-Frame-Options, etc.).
* **🌐 CORS Misconfiguration**: Checks for wildcard origins and credentials allowed, identifying potential cross-origin data leaks.
* **🛡️ CSRF Analysis**: Detects forms without proper CSRF protection, analyzing tokens in hidden inputs, meta tags, and global variables.
* **💉 XSS / HTMLi Analysis**: Evaluates and highlights input fields based on constraints (maxlength, patterns) and detects real-time reflections in the DOM.
* **⚡ DOM Sinks**: Scans inline scripts for dangerous sinks (`innerHTML`, `eval`, `document.write`) interacting with user-controllable sources.
* **🔄 Reflected Parameters**: Automatically catches parameters reflected in the HTML body, scripts, or attributes and assesses severity.
* **📩 PostMessage Listeners**: Inspects `postMessage` event listeners for insecure origins or dangerous handlers.
* **🔓 Sensitive Data Leaks**: Extracts over 40 types of exposed secrets, tokens, API keys (AWS, GCP, Azure, Stripe, GitHub, etc.), and private keys from the page source.
* **☁️ Cloud Infrastructure**: Identifies cloud assets, storage buckets (S3, Azure Blob, GCP Storage), and signed URLs exposed in the application.
* **📡 Live API Collector (cURL)**: Intercepts background XHR and Fetch requests, automatically generating ready-to-use cURL commands for deeper API testing.
* **🗺️ Endpoint Map / JS**: Automatically maps discovered API routes and JavaScript files for easy extraction.
* **🗺️ Source Map Detector & Unpacker**: Discovers exposed JavaScript/CSS source maps (`.map` files), validates accessibility, analyzes frameworks, and enables **one-click ZIP download** of fully reconstructed original source code (`src_unpacked/`).
* **🍪 Cookie Security**: Flags insecure session cookies (e.g., missing HttpOnly or Secure flags).

## 🛠️ Installation

### Google Chrome
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right corner.
3. Click on **Load unpacked**.
4. Select the `chrome_bounty_extension` folder from this repository.

### Mozilla Firefox
1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2. Click on **Load Temporary Add-on...**.
3. Select the `manifest.json` file inside the `firefox_bounty_extension` folder.

## 📋 Usage

1. Click on the 🔍 BountySleuth icon in your browser extension toolbar to open the analyzer dashboard.
2. The extension badge will display the total number of findings (Red for high severity/count, Orange for medium/low).
3. Browse your target application. BountySleuth will passively analyze headers, scripts, and requests in the background.
4. Interact with the application to populate the **Live API Collector** and **XSS** modules.
5. Export your findings seamlessly using the **📋 MD** (Markdown) or **💾 JSON** buttons in the extension popup for your vulnerability reports.

## 📦 Releases

Pre-compiled files for both Google Chrome and Mozilla Firefox are available in the [Releases](https://github.com/sagarbanwa/BountySleuth/releases) section of this repository.

## 📬 Contact

**Security0x0 Research And Development Private Limited**  
📧 Email: [contact@secuirty0x0.com](mailto:contact@secuirty0x0.com)  
🐦 Twitter: [x.com/sagarbanwa](https://x.com/sagarbanwa)

## 📝 Changelog

### v3.4 — Source Map Unpacker & Bug Fixes
- ✨ **New: Source Map Unpacker (📦 Unpack ZIP)** — Reconstructs full original source directories from `.map` files and downloads them as a structured `.zip` with a `src_unpacked/` root folder.
- 🐛 **Fix: ZIP download now works** — Replaced `FileReader.readAsDataURL()` with `URL.createObjectURL()` for Manifest V3 service worker compatibility.
- 🐛 **Fix: Unpack ZIP button always visible** — Removed conditional display logic that hid the button when analysis data wasn't available.
- 🐛 **Fix: CSS source maps now fully analyzed** — Enabled deep content analysis for CSS `.map` files (previously skipped).
- 🐛 **Fix: Release ZIP corruption** — Added `.gitattributes` binary markers to prevent Git from corrupting ZIP files.
- 🏷️ **Branding: Security0x0 Research And Development Private Limited** — Added developer attribution and contact email across all UI elements.

### v3.3 — Source Map Detector
- ✨ Advanced source map discovery (JS, CSS, HTTP headers, webpack/Next.js/Nuxt probing)
- ✨ Deep analysis: framework detection, source count, embedded code leak warnings
- ✨ One-click download of individual `.map` files
- 🐛 Fixed release ZIP corruption via `.gitattributes`

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Do not use BountySleuth on systems you do not own or have explicit permission to test.
