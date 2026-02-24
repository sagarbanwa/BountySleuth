// ============================================================
// BountySleuth v3.5 - Advanced Content Script
// CSRF / XSS / HTMLi / DOM Sink / Cookie / CORS Analysis
// API Collector / Endpoint Mining
// ============================================================

// ---- API Collector Injection (v3.5) ----
// This runs immediately to intercept XHR/Fetch before the page loads fully
(function injectApiCollector() {
    const script = document.createElement('script');
    script.textContent = `
        (function() {
            if (window.__bslt_api_hook) return;
            window.__bslt_api_hook = true;

            function buildCurl(method, url, headers, body) {
                let curl = 'curl -X ' + method + ' "' + url + '"';
                const headerKeys = Object.keys(headers);
                for (let i = 0; i < headerKeys.length; i++) {
                    const k = headerKeys[i];
                    const escapedVal = headers[k].replace(/"/g, '\\\\"' + '"' + '\\\\"');
                    curl += ' -H "' + k + ': ' + escapedVal + '"';
                }
                
                if (body && typeof body === 'string') {
                    const escapedBody = body.replace(/'/g, "'\\\\''");
                    curl += " --data '" + escapedBody + "'";
                } else if (body && body instanceof FormData) {
                    curl += " --data '[FormData Object]'";
                } else if (body) {
                    try {
                        const jsonBody = JSON.stringify(body).replace(/'/g, "'\\\\''");
                        curl += " --data '" + jsonBody + "'";
                    } catch(e) {}
                }
                return curl;
            }

            function sendApi(method, url, headers, body) {
                if (!url || typeof url !== 'string' || url.startsWith('chrome-extension://')) return;
                
                // Exclude obvious static files from API collector
                if (/\\.(css|woff2?|ttf|eot|png|jpe?g|gif|svg|ico|webp|avif|mp4|webm|js)(\\?.*)?$/i.test(url.split('#')[0])) return;

                const curlExt = buildCurl(method, url, headers, body);
                window.postMessage({ type: 'BS_API_INTERCEPT', method: method, url: url, curl: curlExt }, '*');
            }

            // Hook XHR
            const origOpen = window.XMLHttpRequest.prototype.open;
            const origSetRequestHeader = window.XMLHttpRequest.prototype.setRequestHeader;
            const origSend = window.XMLHttpRequest.prototype.send;
            
            window.XMLHttpRequest.prototype.open = function(method, url) {
                this._bs_method = method ? method.toUpperCase() : 'GET';
                this._bs_url = url;
                this._bs_headers = {};
                return origOpen.apply(this, arguments);
            };
            
            window.XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
                if (this._bs_headers) this._bs_headers[header] = value;
                return origSetRequestHeader.apply(this, arguments);
            };
            
            window.XMLHttpRequest.prototype.send = function(body) {
                try {
                    sendApi(this._bs_method, this._bs_url, this._bs_headers || {}, body);
                } catch(e) {}
                return origSend.apply(this, arguments);
            };

            // Hook Fetch
            const origFetch = window.fetch;
            window.fetch = async function(...args) {
                try {
                    const req = args[0];
                    const opts = args[1] || {};
                    
                    let url = '';
                    let method = 'GET';
                    let headers = {};
                    let body = opts.body;
                    
                    if (typeof req === 'string') {
                        url = req;
                        method = (opts.method || 'GET').toUpperCase();
                        headers = opts.headers || {};
                    } else if (req && typeof req === 'object') {
                        url = req.url || '';
                        method = (req.method || opts.method || 'GET').toUpperCase();
                        if (req.headers && typeof req.headers.forEach === 'function') {
                            req.headers.forEach((val, key) => headers[key] = val);
                        }
                        if (opts.headers) {
                            for (let k in opts.headers) headers[k] = opts.headers[k];
                        }
                    }
                    sendApi(method, url, headers, body);
                } catch(e) {}
                return origFetch.apply(this, args);
            };
        })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
})();

// Global array for live apis
const _liveApis = [];

// Listen for intercepted APIs
window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.type !== 'BS_API_INTERCEPT') return;

    // De-duplicate (same curl)
    if (!_liveApis.some(api => api.curl === event.data.curl)) {
        _liveApis.push({
            method: event.data.method,
            url: event.data.url,
            curl: event.data.curl
        });

        // Save to storage incrementally
        const host = window.location.hostname;
        chrome.storage.local.get([host], (result) => {
            const data = result[host] || {};
            data.live_apis = _liveApis;
            const updateObj = {};
            updateObj[host] = data;
            chrome.storage.local.set(updateObj);
        });
    }
});

// ---- CSRF Token Patterns ----
const CSRF_TOKEN_NAMES = [
    'csrf', 'csrf_token', 'csrf-token', '_csrf', '_csrf_token',
    'xsrf', 'xsrf_token', 'xsrf-token', '_xsrf',
    'authenticity_token',
    '_token',
    '__requestverificationtoken', 'requestverificationtoken',
    'antiforgery', 'antiforgerytoken',
    'csrfmiddlewaretoken',
    'form_build_id',
    'nonce', '_nonce',
    'wp_nonce', '_wpnonce',
    'security', '_security',
    'token', 'csrfhash',
    'csrftoken',
    'x-csrf-token', 'x-xsrf-token',
    'laravel_token',
    'yii_csrf_token', '_csrf-frontend', '_csrf-backend'
];

const CSRF_HEADER_NAMES = [
    'x-csrf-token',
    'x-xsrf-token',
    'x-xsrf-token-header',
    'x-csrftoken',
    'x-csrf',
    'x-xsrf',
    'x-request-verification-token',
    'requestverificationtoken',
    '__requestverificationtoken',
    'anti-csrf-token',
    'x-anti-forgery-token',
    'x-csrf-header',
    'x-xsrf-header',
    'x-csrf-protection',
    'x-csrf-token-value',
    'x-requested-with'
];

// ---- XSS Dangerous DOM Sinks ----
const DOM_SINKS = [
    'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'srcdoc',
    'document.write', 'document.writeln',
    'eval', 'Function',
    'setTimeout', 'setInterval',
    'location', 'location.href', 'location.assign', 'location.replace',
    'window.open',
    'element.src', 'script.src', 'iframe.src',
    'element.setAttribute',
    'Range.createContextualFragment',
    'postMessage'
];
// ---- Canary Payload ----
const CANARY = 'bslt' + Math.random().toString(36).substring(2, 8);

// ---- PostMessage Listener Detection ----
const DANGEROUS_SOURCES = ['/*', 'origin', 'source'];

// ---- Sensitive Data Patterns (Enhanced) ----
const LEAK_PATTERNS = {

    // === GENERIC TOKENS ===
    'Generic API Key': /\bapi[_-]?key\b\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?/gi,
    'Generic Secret': /\bsecret\b\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?/gi,
    'Bearer Token': /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/g,
    'JWT Token': /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b/g,

    // === AWS ===
    'AWS Access Key': /\bAKIA[0-9A-Z]{16}\b/g,
    'AWS Secret Key': /\baws(.{0,20})?(secret|access)?.{0,5}["']?[A-Za-z0-9\/+=]{40}\b/gi,
    'AWS S3 URL': /\b[a-z0-9.-]+\.s3\.amazonaws\.com\b/gi,
    'AWS CloudFront URL': /\b[a-z0-9.-]+\.cloudfront\.net\b/gi,

    // === GCP ===
    'Google API Key': /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    'Firebase URL': /\bhttps:\/\/[a-z0-9-]+\.firebaseio\.com\b/gi,
    'GCP Service Account': /"type":\s*"service_account"/g,

    // === AZURE ===
    'Azure Storage Key': /\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;/gi,
    'Azure SAS Token': /\bsv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[rwdlacupx]+&se=/gi,

    // === GITHUB ===
    'GitHub Token': /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    'GitHub Fine Token': /\bgithub_pat_[A-Za-z0-9_]{80,}\b/g,

    // === STRIPE ===
    'Stripe Secret Key': /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
    'Stripe Publishable Key': /\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b/g,

    // === SLACK ===
    'Slack Token': /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g,
    'Slack Webhook': /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+\b/g,

    // === TWILIO ===
    'Twilio SID': /\bAC[a-f0-9]{32}\b/gi,
    'Twilio API Key': /\bSK[a-f0-9]{32}\b/gi,

    // === SENDGRID ===
    'SendGrid API Key': /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,

    // === MAILGUN ===
    'Mailgun API Key': /\bkey-[0-9a-f]{32}\b/gi,

    // === PAYPAL ===
    'PayPal Client ID': /\bA21[A-Za-z0-9_-]{40,}\b/g,

    // === HEROKU ===
    'Heroku API Key': /\bheroku[a-f0-9]{32}\b/gi,

    // === DIGITALOCEAN ===
    'DigitalOcean Token': /\bdo[a-f0-9]{64}\b/gi,

    // === SHOPIFY ===
    'Shopify Access Token': /\bshpat_[A-Za-z0-9]{32}\b/g,

    // === PRIVATE KEYS ===
    'RSA Private Key': /-----BEGIN RSA PRIVATE KEY-----/g,
    'OpenSSH Private Key': /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    'EC Private Key': /-----BEGIN EC PRIVATE KEY-----/g,
    'PGP Private Key': /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,

    // === DATABASE URLS ===
    'MongoDB URI': /\bmongodb(?:\+srv)?:\/\/[^\s"'`]+/gi,
    'Postgres URI': /\bpostgres:\/\/[^\s"'`]+/gi,
    'MySQL URI': /\bmysql:\/\/[^\s"'`]+/gi,
    'Redis URI': /\bredis:\/\/[^\s"'`]+/gi,

    // === GRAPHQL ===
    'GraphQL Endpoint': /\/graphql\b/gi,

    // === BASIC AUTH URL ===
    'Basic Auth URL': /\bhttps?:\/\/[^:@\s]+:[^:@\s]+@[^\/\s]+\b/gi,

    // === CLOUD STORAGE ===
    'Google Storage': /\bstorage\.googleapis\.com\/[^\s"'`]+/gi,
    'Azure Blob': /\bblob\.core\.windows\.net\/[^\s"'`]+/gi

};

// ---- Cloud Asset Patterns ----
const CLOUD_PATTERNS = {

    // ===== AWS =====
    'S3 Virtual Hosted': /\b[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com\b/gi,
    'S3 Path Style': /\bs3(?:-[a-z0-9-]+)?\.amazonaws\.com\/[a-z0-9.-]+\b/gi,
    'S3 Website Endpoint': /\b[a-z0-9.-]+\.s3-website-[a-z0-9-]+\.amazonaws\.com\b/gi,
    'CloudFront URL': /\b[a-z0-9-]+\.cloudfront\.net\b/gi,
    'AWS Signed URL': /\bX-Amz-Algorithm=AWS4-HMAC-SHA256\b/gi,

    // ===== AZURE =====
    'Azure Blob': /\b[a-z0-9.-]+\.blob\.core\.windows\.net\b/gi,
    'Azure File': /\b[a-z0-9.-]+\.file\.core\.windows\.net\b/gi,
    'Azure Queue': /\b[a-z0-9.-]+\.queue\.core\.windows\.net\b/gi,
    'Azure Table': /\b[a-z0-9.-]+\.table\.core\.windows\.net\b/gi,
    'Azure SAS Token': /\bsv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[rwdlacupx]+\b/gi,

    // ===== GCP =====
    'GCP Storage JSON API': /\bstorage\.googleapis\.com\/[a-z0-9._-]+\b/gi,
    'GCP Storage Media Link': /\bhttps:\/\/storage.googleapis.com\/[a-z0-9._-]+/gi,
    'GCP Appspot': /\b[a-z0-9-]+\.appspot\.com\b/gi,
    'Firebase Storage': /\bfirebasestorage\.googleapis\.com\b/gi,
    'Firebase DB': /\bhttps:\/\/[a-z0-9-]+\.firebaseio\.com\b/gi,

    // ===== DIGITALOCEAN =====
    'DigitalOcean Space': /\b[a-z0-9.-]+\.[a-z0-9-]+\.digitaloceanspaces\.com\b/gi,

    // ===== CLOUDFLARE =====
    'Cloudflare R2': /\b[a-z0-9.-]+\.r2\.cloudflarestorage\.com\b/gi,
    'Cloudflare Pages': /\b[a-z0-9-]+\.pages\.dev\b/gi,

    // ===== BACKBLAZE =====
    'Backblaze B2': /\bs3\.[a-z0-9-]+\.backblazeb2\.com\b/gi,

    // ===== SUPABASE =====
    'Supabase Storage': /\b[a-z0-9-]+\.supabase\.co\/storage\b/gi,

    // ===== WASABI =====
    'Wasabi Storage': /\b[a-z0-9.-]+\.s3\.wasabisys\.com\b/gi

};

// ---- Main Scanner ----
async function scanPage() {
    const findings = {
        csrf: [],
        xss: [],
        dom_sinks: [],
        cookies: [],
        cors: null,
        security_headers: [],
        reflected_params: [],
        post_messages: [],
        leaks: [],
        cloud_assets: [],
        endpoints: new Set(),
        js_files: new Set(),
        js_protections: []
    };

    // =============================================
    // 1. CSRF ANALYSIS (Enhanced)
    // =============================================
    scanCSRF(findings);

    // =============================================
    // 2. XSS / HTMLi ANALYSIS (Enhanced)
    // =============================================
    scanXSS(findings);

    // =============================================
    // 3. DOM SINK & JS PROTECTION ANALYSIS (v3.3)
    // =============================================
    scanDOMSinks(findings);
    scanJSProtections(findings);

    // =============================================
    // 4. COOKIE SECURITY ANALYSIS
    // =============================================
    scanCookies(findings);

    // =============================================
    // 5. REFLECTED PARAMETER DETECTION
    // =============================================
    scanReflectedParams(findings);

    // =============================================
    // 6. POSTMESSAGE LISTENER ANALYSIS
    // =============================================
    scanPostMessages(findings);

    // =============================================
    // 7. SENSITIVE DATA LEAK SCAN (Async)
    // =============================================
    await scanLeaks(findings);

    // =============================================
    // 8. CLOUD ASSET DETECTION
    // =============================================
    scanCloudAssets(findings);

    // =============================================
    // 9. ENDPOINT MINING
    // =============================================
    mineEndpoints(findings);

    // =============================================
    // 10. SAVE ALL FINDINGS
    // =============================================
    saveFindings(findings);
}

// ---- CSRF Scanner ----
function scanCSRF(findings) {
    const forms = document.querySelectorAll('form');

    // Check global meta tokens
    const globalMetaToken = document.querySelector(
        'meta[name="csrf-token"], meta[name="xsrf-token"], meta[name="csrf-param"], meta[name="_token"]'
    );

    // Check global JS variables for tokens
    let globalJsToken = false;
    try {
        const scriptTags = document.querySelectorAll('script:not([src])');
        scriptTags.forEach(s => {
            const text = s.textContent;
            if (/csrf|xsrf|_token|antiforgery/i.test(text) && /["'][a-zA-Z0-9+\/=]{20,}["']/i.test(text)) {
                globalJsToken = true;
            }
        });
    } catch (e) { /* safe to continue */ }

    forms.forEach(form => {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (method === 'GET') return;

        let hasToken = false;
        let tokenSource = '';

        // Check hidden inputs
        form.querySelectorAll('input[type="hidden"]').forEach(input => {
            const name = (input.name || '').toLowerCase();
            const id = (input.id || '').toLowerCase();
            if (CSRF_TOKEN_NAMES.some(t => name.includes(t) || id.includes(t))) {
                hasToken = true;
                tokenSource = `hidden input: ${input.name}`;
            }
        });

        // Check global meta tag
        if (!hasToken && globalMetaToken) {
            hasToken = true;
            tokenSource = `meta tag: ${globalMetaToken.getAttribute('name')}`;
        }

        // Check global JS variable
        if (!hasToken && globalJsToken) {
            hasToken = true;
            tokenSource = 'inline JS variable';
        }

        // Check data attributes on form
        if (!hasToken) {
            const formAttrs = form.getAttributeNames();
            formAttrs.forEach(attr => {
                if (/csrf|token|nonce/i.test(attr)) {
                    hasToken = true;
                    tokenSource = `form attribute: ${attr}`;
                }
            });
        }

        if (!hasToken) {
            const action = form.getAttribute('action') || window.location.pathname;
            const formId = form.getAttribute('id') || form.getAttribute('name') || 'unnamed';
            const inputCount = form.querySelectorAll('input, textarea, select').length;

            findings.csrf.push({
                action: action,
                method: method,
                formId: formId,
                inputCount: inputCount,
                severity: method === 'POST' ? 'HIGH' : 'MEDIUM'
            });
        }
    });

    // Check if AJAX requests lack CSRF headers (intercept prototype)
    checkAjaxCSRF(findings);
}

// Intercept XHR/fetch to see if they carry CSRF headers
function checkAjaxCSRF(findings) {
    // We can't fully intercept without injecting into the page context,
    // but we can check if common AJAX frameworks set up default headers
    try {
        const scriptTags = document.querySelectorAll('script:not([src])');
        let hasAjaxCSRFSetup = false;

        scriptTags.forEach(s => {
            const text = s.textContent;
            // Check for axios defaults, jQuery ajaxSetup, fetch wrappers
            if (/axios\.defaults\.headers.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/\$\.ajaxSetup.*headers.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/beforeSend.*setRequestHeader.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/x-csrf-token|x-xsrf-token/i.test(text)) hasAjaxCSRFSetup = true;
        });

        if (!hasAjaxCSRFSetup && document.querySelectorAll('form[method="POST"]').length === 0) {
            // SPA with no forms and no visible CSRF setup -> flag it
            const xhrScripts = document.querySelectorAll('script[src*="axios"], script[src*="jquery"]');
            if (xhrScripts.length > 0) {
                findings.csrf.push({
                    action: '(SPA AJAX calls)',
                    method: 'XHR/FETCH',
                    formId: 'n/a',
                    inputCount: 0,
                    severity: 'MEDIUM',
                    note: 'SPA detected with AJAX library but no visible CSRF header setup'
                });
            }
        }
    } catch (e) { /* safe to continue */ }
}

// ---- XSS / HTMLi Scanner (Enhanced v3.3) ----
function scanXSS(findings) {
    const urlParams = new URL(window.location.href).searchParams;
    const allParamNames = Array.from(urlParams.keys()).map(k => k.toLowerCase());

    const selectors = [
        'input[type="text"]', 'input[type="search"]', 'input[type="url"]',
        'input[type="email"]', 'input[type="tel"]', 'input[type="password"]',
        'input:not([type])', 'textarea'
    ];

    document.querySelectorAll(selectors.join(', ')).forEach(input => {
        if (input.type === 'hidden') return;

        const issues = [];
        const name = input.name || input.id || 'unnamed';
        const maxLen = input.getAttribute('maxlength');
        const pattern = input.getAttribute('pattern');
        const isReflectedParam = allParamNames.includes(name.toLowerCase());

        let protectionLevel = 'LOW'; // Default assumption: Vulnerable (GREEN)

        // Constraint Checks (Moves to RED)
        if (maxLen && parseInt(maxLen) <= 50) {
            issues.push(`strict maxlength (${maxLen})`);
            protectionLevel = 'HIGH';
        } else if (!maxLen) {
            issues.push('no maxlength');
        } else {
            issues.push(`high maxlength (${maxLen})`);
        }

        if (pattern) {
            issues.push('pattern validation');
            protectionLevel = 'HIGH';
        }

        const domSinks = ['onload', 'onerror', 'onfocus', 'onblur', 'onchange', 'oninput', 'onkeyup', 'onkeydown', 'onkeypress', 'onclick', 'ondblclick', 'onmouseover', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmousedown', 'onmouseup', 'onsubmit', 'onreset', 'onresize', 'onscroll', 'oncontextmenu', 'onanimationstart', 'onanimationend', 'ontransitionend', 'ontoggle', 'onpointerover', 'onpointerenter'];
        let hasDangerousEvent = false;
        domSinks.forEach(evt => {
            if (input.hasAttribute(evt)) {
                hasDangerousEvent = true;
            }
        });
        if (hasDangerousEvent) {
            issues.push('has inline event handler');
            if (protectionLevel !== 'HIGH') protectionLevel = 'MEDIUM'; // Suspicious (YELLOW)
        }

        // Reflection Check (Moves to YELLOW if unprotected)
        if (isReflectedParam && protectionLevel === 'LOW') {
            issues.push('name matches URL param');
            protectionLevel = 'MEDIUM';
        }

        if (input.value && input.value.length > 2) {
            const occurrences = document.body.innerHTML.split(input.value).length - 1;
            if (occurrences > 1) {
                issues.push('value reflected in DOM');
                if (protectionLevel === 'LOW') protectionLevel = 'MEDIUM';
            }
        }

        // Determine Final Severity for UI display (Inverted logic for Hunters: LOW protection = HIGH vuln)
        // Red = Protected/Low Vuln. Yellow = Medium Vuln/Reflects. Green = High Vuln/Unprotected.
        let vulnSeverity = 'GREEN';
        if (protectionLevel === 'HIGH') vulnSeverity = 'RED';
        else if (protectionLevel === 'MEDIUM') vulnSeverity = 'YELLOW';

        findings.xss.push({
            name: name,
            id: input.id || 'no-id',
            type: input.type || input.tagName.toLowerCase(),
            issues: issues,
            severity: vulnSeverity, // 'GREEN', 'YELLOW', 'RED'
            isReflected: isReflectedParam
        });
    });

    // 2. Visually highlight flagged inputs
    highlightInputs(findings);
}

// Inject harmless canary strings into inputs for reflection testing
function injectCanaries(findings) {
    const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
    const canaryMap = {};

    inputs.forEach((input, idx) => {
        const fieldName = input.name || input.id || `field_${idx}`;
        const fieldCanary = `${CANARY}_${idx}`;
        canaryMap[fieldName] = fieldCanary;
        // Store canaries for later reflection check (don't actually type into input)
    });

    // Save canary map for popup to reference
    const host = window.location.hostname;
    chrome.storage.local.get([host], (result) => {
        const data = result[host] || {};
        data._canaryMap = canaryMap;
        data._canaryBase = CANARY;
        const updateObj = {};
        updateObj[host] = data;
        chrome.storage.local.set(updateObj);
    });
}

// Highlight inputs based on Vuln Severity (Green=Good Target, Red=Protected Target)
function highlightInputs(findings) {
    findings.xss.forEach(xssField => {
        const el = document.querySelector(`[name="${xssField.name}"]`) || document.getElementById(xssField.id);
        if (el) {
            if (xssField.severity === 'GREEN') {
                // Highly Vulnerable / Unprotected
                el.style.border = '2px dotted #3fb950'; // Success green
                el.style.boxShadow = '0 0 8px rgba(63, 185, 80, 0.4)';
                el.style.backgroundColor = 'rgba(63, 185, 80, 0.05)';
            } else if (xssField.severity === 'YELLOW') {
                // Potential Reflection or Medium protection
                el.style.border = '2px dotted #d29922'; // Warning yellow
                el.style.boxShadow = '0 0 6px rgba(210, 153, 34, 0.3)';
                el.style.backgroundColor = 'rgba(210, 153, 34, 0.05)';
            } else if (xssField.severity === 'RED') {
                // Heavily protected
                el.style.border = '2px dotted #f85149'; // Danger red
                el.style.backgroundColor = 'rgba(248, 81, 73, 0.02)';
            }
            el.title = `BountySleuth: ${xssField.issues.join(', ')}`;
        }
    });
}

// ---- JS Protection Scanner (v3.3) ----
function scanJSProtections(findings) {
    try {
        const scripts = document.querySelectorAll('script');
        let htmlSource = document.documentElement.outerHTML.toLowerCase();

        if (htmlSource.includes('dompurify') || window.DOMPurify) {
            findings.js_protections.push('DOMPurify');
        }
        if (htmlSource.includes('xss(') || htmlSource.includes('js-xss')) {
            findings.js_protections.push('js-xss');
        }
        if (htmlSource.includes('sanitizehtml') || window.sanitizeHtml) {
            findings.js_protections.push('sanitize-html');
        }

        // Scan script texts for custom replace filters
        const inlines = document.querySelectorAll('script:not([src])');
        inlines.forEach(script => {
            const code = script.textContent;
            if (/\.replace\(\s*\/[^/]*(<|>|script|on\w+|javascript:|data:|eval)[^/]*\/[gimuy]*\s*,/i.test(code)) {
                if (!findings.js_protections.includes('Custom Regex Filter')) {
                    findings.js_protections.push('Custom Regex Filter');
                }
            }
        });
    } catch (e) { }
}

// ---- DOM Sink Scanner ----
function scanDOMSinks(findings) {
    try {
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
            const code = script.textContent;
            if (!code || code.length < 10) return;

            DOM_SINKS.forEach(sink => {
                // Use regex to find dangerous patterns
                const regex = new RegExp(`\\.${sink}\\s*[=(]`, 'gi');
                if (regex.test(code)) {
                    // Check if it involves user-controllable sources
                    const hasSources = /location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|URLSearchParams|postMessage|localStorage|sessionStorage/i.test(code);

                    findings.dom_sinks.push({
                        sink: sink,
                        hasUserSource: hasSources,
                        scriptSnippet: code.substring(0, 80).replace(/\s+/g, ' ').trim() + '...',
                        severity: hasSources ? 'HIGH' : 'LOW'
                    });
                }
            });
        });
    } catch (e) { /* safe to continue */ }
}

// ---- Cookie Security Scanner ----
function scanCookies(findings) {
    try {
        const cookies = document.cookie.split(';').filter(c => c.trim().length > 0);
        cookies.forEach(cookie => {
            const parts = cookie.trim().split('=');
            const name = parts[0].trim();
            const value = parts.slice(1).join('=').trim();
            const issues = [];

            // Since we are reading from document.cookie, these cookies are NOT httpOnly
            issues.push('accessible via JS (not HttpOnly)');

            // Check for session-like cookie names
            const isSession = /\b(session|sess(?:ion)?|sid|phpsessid|aspsessionid|token|id[_-]?token|access[_-]?token|refresh[_-]?token|auth(?:orization)?|jwt|bearer|login|user(?:name)?|apikey|api[_-]?key|client[_-]?secret|secret|csrf|xsrf)\b/i.test(name);
            if (isSession) {
                issues.push('appears to be a session cookie');
            }

            // Check if page is HTTP (not HTTPS) - cookie could leak
            if (window.location.protocol === 'http:') {
                issues.push('served over HTTP (no Secure flag protection)');
            }

            findings.cookies.push({
                name: name,
                valuePreview: value.substring(0, 20) + (value.length > 20 ? '...' : ''),
                issues: issues,
                isSession: isSession,
                severity: isSession ? 'HIGH' : 'INFO'
            });
        });
    } catch (e) { /* safe to continue */ }
}

// ---- Reflected Parameter Detection (Advanced v3.1) ----
function scanReflectedParams(findings) {
    try {
        const params = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash.replace('#', '?'));
        const bodyHTML = document.body.innerHTML;
        const bodyText = document.body.textContent;

        const allParams = [...params.entries(), ...hashParams.entries()];
        const specialChars = ['<', '>', '"', "'", '/', '\\', '(', ')'];

        allParams.forEach(([key, value]) => {
            if (value.length < 3) return;

            if (bodyHTML.includes(value)) {
                const contexts = [];
                const unencoded = [];

                // 1. Detect Contexts
                // Is it in a script block?
                const scriptRegex = new RegExp(`<script[^>]*>[^<]*${escapeRegex(value)}[^<]*<\/script>`, 'i');
                if (scriptRegex.test(bodyHTML)) contexts.push('SCRIPT');

                // Is it in an attribute?
                const attrRegex = new RegExp(`\\s[a-z0-9_-]+=['"][^'"]*${escapeRegex(value)}[^'"]*['"]`, 'i');
                if (attrRegex.test(bodyHTML)) {
                    // Check if it's a URL attribute
                    const urlAttrRegex = new RegExp(`\\s(href|src|action|formaction|data)=['"][^'"]*${escapeRegex(value)}[^'"]*['"]`, 'i');
                    if (urlAttrRegex.test(bodyHTML)) contexts.push('URL_ATTR');
                    else contexts.push('ATTR');
                }

                // Is it in text content?
                if (bodyText.includes(value)) {
                    // Double check it's not JUST in an attribute
                    const textRegex = new RegExp(`>[^<]*${escapeRegex(value)}[^<]*<`, 'i');
                    if (textRegex.test(bodyHTML)) contexts.push('TEXT');
                }

                // fallback
                if (contexts.length === 0) contexts.push('HTML_UNKNOWN');

                // 2. Search for unencoded special characters linked to this value
                // In a real world scenario, the user would provide a param like ?p=test<>"'
                // We check if those specific chars in the current value are reflected unencoded
                specialChars.forEach(char => {
                    if (value.includes(char)) {
                        // Check if the character appears literally in the HTML reflection
                        // Note: This is a heuristic. We assume the first reflection we find is the one to audit.
                        if (bodyHTML.includes(value)) {
                            unencoded.push(char);
                        }
                    }
                });

                findings.reflected_params.push({
                    param: key,
                    value: value.substring(0, 40),
                    contexts: contexts,
                    unencoded: unencoded,
                    severity: judgeReflectionSeverity(contexts, unencoded)
                });
            }
        });
    } catch (e) { /* safe to continue */ }
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function judgeReflectionSeverity(contexts, unencoded) {
    if (contexts.includes('SCRIPT')) return 'CRITICAL';
    if (unencoded.includes('<') || unencoded.includes('>')) {
        if (contexts.includes('TEXT')) return 'CRITICAL';
    }
    if (unencoded.includes('"') || unencoded.includes("'")) {
        if (contexts.includes('ATTR')) return 'HIGH';
    }
    if (contexts.includes('URL_ATTR')) return 'HIGH';
    return 'MEDIUM';
}

// ---- PostMessage Scanner ----
function scanPostMessages(findings) {
    try {
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
            const code = script.textContent;
            if (code.includes('addEventListener') && code.includes('message')) {
                const issues = [];
                if (!code.includes('event.origin') && !code.includes('.origin')) {
                    issues.push('Missing origin validation');
                }

                findings.post_messages.push({
                    snippet: code.substring(0, 100).trim() + '...',
                    issues: issues,
                    severity: issues.length > 0 ? 'HIGH' : 'LOW'
                });
            }
        });
    } catch (e) { }
}

// ---- Sensitive Data Leak Scanner (Enhanced) ----
async function scanLeaks(findings) {
    // Helper to scan text line by line
    const scanLines = (text, sourceUrl) => {
        const lines = text.split('\n');
        lines.forEach((line, index) => {
            Object.keys(LEAK_PATTERNS).forEach(key => {
                const regex = LEAK_PATTERNS[key];
                regex.lastIndex = 0; // reset
                let match;
                while ((match = regex.exec(line)) !== null) {
                    const matchedValue = match[1] || match[0];
                    if (matchedValue.length < 5) continue; // ignore short false positives

                    // check if we already found this exact value to prevent duplicates
                    if (findings.leaks.some(l => l.value === matchedValue)) continue;

                    findings.leaks.push({
                        type: key,
                        value: matchedValue,
                        snippet: line.substring(Math.max(0, match.index - 30), Math.min(line.length, match.index + match[0].length + 30)).trim(),
                        line: index + 1,
                        source: sourceUrl,
                        severity: 'HIGH'
                    });
                }
            });
        });
    };

    // 1. Scan Main Document HTML
    scanLines(document.documentElement.outerHTML, window.location.href);

    // 2. Scan Same-Origin Scripts via fetch
    const scripts = document.querySelectorAll('script[src]');
    const fetchPromises = Array.from(scripts).map(async (s) => {
        const src = s.src;
        if (src && src.startsWith(window.location.origin)) {
            try {
                const resp = await fetch(src);
                if (resp.ok) {
                    const text = await resp.text();
                    scanLines(text, src);
                }
            } catch (e) { /* ignore CORS / network errors */ }
        }
    });

    await Promise.all(fetchPromises);
}

// ---- Cloud Asset Scanner ----
function scanCloudAssets(findings) {
    const bodyHTML = document.documentElement.outerHTML;
    Object.keys(CLOUD_PATTERNS).forEach(key => {
        const regex = CLOUD_PATTERNS[key];
        let match;
        while ((match = regex.exec(bodyHTML)) !== null) {
            findings.cloud_assets.push({
                type: key,
                url: match[0],
                severity: 'MEDIUM'
            });
        }
    });
}

// ---- Endpoint Miner (Filtered v3.5) ----
function mineEndpoints(findings) {
    const staticExtRegex = /\.(css|map|woff2?|ttf|eot|otf|png|jpe?g|gif|svg|ico|webp|avif|bmp|mp4|webm|mp3|wav|ogg|m4a|mov|avi|pdf|docx?|xlsx?|pptx?|txt|rtf|zip|rar|7z|tar|gz|tgz|xml|json|apk|exe|dmg|iso)(\?.*)?$/i;
    const jsRegex = /\.js(\?.*)?$/i;

    // Collect from various tags
    const links = document.querySelectorAll('a[href], script[src], img[src], link[href], iframe[src], form[action]');
    links.forEach(el => {
        const url = el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('action');
        if (url && !url.startsWith('#') && !url.startsWith('javascript:')) {
            try {
                const absoluteUrl = new URL(url, window.location.href).href;
                if (jsRegex.test(absoluteUrl)) {
                    findings.js_files.add(absoluteUrl);
                } else if (!staticExtRegex.test(absoluteUrl)) {
                    findings.endpoints.add(absoluteUrl);
                }
            } catch (e) { }
        }
    });

    // Also look for strings that look like relative paths /api/v1/...
    const bodyText = document.body.innerHTML;
    const pathRegex = /\"(\/[a-zA-Z0-9\._\-\/]+[a-zA-Z0-9\/])\"/g;
    let pathMatch;
    while ((pathMatch = pathRegex.exec(bodyText)) !== null) {
        if (pathMatch[1].length > 4 && pathMatch[1].includes('/')) {
            if (jsRegex.test(pathMatch[1])) {
                findings.js_files.add(pathMatch[1]);
            } else if (!staticExtRegex.test(pathMatch[1])) {
                findings.endpoints.add(pathMatch[1]);
            }
        }
    }
}

// ---- Save Findings to Storage ----
function saveFindings(findings) {
    const host = window.location.hostname;
    chrome.storage.local.get([host], (result) => {
        const data = result[host] || { wafs: [], live_apis: [] };

        data.csrf = findings.csrf;
        data.xss = findings.xss;
        data.dom_sinks = findings.dom_sinks;
        data.cookies = findings.cookies;
        data.reflected_params = findings.reflected_params;
        data.post_messages = findings.post_messages;
        data.leaks = findings.leaks;
        data.cloud_assets = findings.cloud_assets;
        data.endpoints = Array.from(findings.endpoints);
        data.js_files = Array.from(findings.js_files);
        data.js_protections = findings.js_protections;
        data.lastScan = new Date().toISOString();
        data.pageUrl = window.location.href;

        const updateObj = {};
        updateObj[host] = data;
        chrome.storage.local.set(updateObj);
    });
}

// ---- Run on page load ----
scanPage();

// ---- Listen for manual rescan ----
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'rescan') {
        scanPage();
        sendResponse({ status: 'done' });
    }
});
