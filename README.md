# 🔍 BountySleuth - Web Sec Analyzer

**BountySleuth** is a professional bug bounty companion and universal web security scanner available as a browser extension for both Chrome and Firefox. It passively monitors and actively analyzes web applications for common vulnerabilities, misconfigurations, and sensitive data exposures while you browse.

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

Pre-compiled files for both Google Chrome and Mozilla Firefox are available in the [releases](./releases) directory.

## 📬 Contact

For questions or feedback, reach out on X/Twitter: [x.com/sagarbanwa](https://x.com/sagarbanwa)

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Do not use BountySleuth on systems you do not own or have explicit permission to test.
