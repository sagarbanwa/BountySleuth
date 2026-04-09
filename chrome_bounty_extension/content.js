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
        js_protections: [],
        sourcemaps: [],
        sri_issues: [], // Subresource Integrity issues
        host_header: [] // Host Header Injection findings
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
    // 10. SOURCE MAP DETECTION
    // =============================================
    await scanSourceMaps(findings);

    // =============================================
    // 11. SUBRESOURCE INTEGRITY (SRI) CHECK
    // =============================================
    scanSRI(findings);

    // =============================================
    // 12. HOST HEADER INJECTION DETECTION
    // =============================================
    scanHostHeaderInjection(findings);

    // =============================================
    // 13. SAVE ALL FINDINGS
    // =============================================
    saveFindings(findings);
}

// ---- CSRF Scanner (Enhanced v3.6.5 - Advanced Token Analysis) ----
function scanCSRF(findings) {
    const forms = document.querySelectorAll('form');

    // Check global meta tokens
    const globalMetaToken = document.querySelector(
        'meta[name="csrf-token"], meta[name="xsrf-token"], meta[name="csrf-param"], meta[name="_token"]'
    );
    const globalMetaValue = globalMetaToken ? (globalMetaToken.getAttribute('content') || '') : '';

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

    // Collect cookie values for Double Submit Cookie detection
    const cookieValues = [];
    try {
        document.cookie.split(';').forEach(c => {
            const val = (c.split('=')[1] || '').trim();
            if (val.length >= 10) cookieValues.push(val);
        });
    } catch (e) { /* ignore */ }

    // Collect all token values to detect static/duplicate tokens
    const allTokenValues = [];

    forms.forEach(form => {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        if (method === 'GET') return;

        const action = form.getAttribute('action') || window.location.pathname;
        const formId = form.getAttribute('id') || form.getAttribute('name') || 'unnamed';
        const inputCount = form.querySelectorAll('input, textarea, select').length;

        let hasToken = false;
        let tokenSource = '';
        let tokenValue = '';
        let tokenIssues = [];

        // Check hidden inputs for CSRF tokens
        form.querySelectorAll('input[type="hidden"]').forEach(input => {
            const name = (input.name || '').toLowerCase();
            const id = (input.id || '').toLowerCase();
            if (CSRF_TOKEN_NAMES.some(t => name.includes(t) || id.includes(t))) {
                hasToken = true;
                tokenSource = `hidden input: ${input.name}`;
                tokenValue = input.value || '';
            }
        });

        // Check global meta tag
        if (!hasToken && globalMetaToken) {
            hasToken = true;
            tokenSource = `meta tag: ${globalMetaToken.getAttribute('name')}`;
            tokenValue = globalMetaValue;
        }

        // Check global JS variable
        if (!hasToken && globalJsToken) {
            hasToken = true;
            tokenSource = 'inline JS variable';
            tokenValue = '(dynamic)';
        }

        // Check data attributes on form
        if (!hasToken) {
            const formAttrs = form.getAttributeNames();
            formAttrs.forEach(attr => {
                if (/csrf|token|nonce/i.test(attr)) {
                    hasToken = true;
                    tokenSource = `form attribute: ${attr}`;
                    tokenValue = form.getAttribute(attr) || '';
                }
            });
        }

        // Detect sensitive form actions
        const actionLower = action.toLowerCase();
        const isSensitiveAction = /login|logout|register|signup|password|reset|change|update|delete|remove|transfer|payment|pay|checkout|admin|settings|profile|account/i.test(actionLower);
        const formHtml = form.innerHTML.toLowerCase();
        const hasSensitiveFields = /password|email|card|cvv|ssn|credit|bank|amount|transfer/i.test(formHtml);

        if (!hasToken) {
            // ===== NO TOKEN FOUND =====
            let verdict = '🚨 CSRF POSSIBLE — No anti-CSRF token found';
            let severity = 'HIGH';

            if (isSensitiveAction || hasSensitiveFields) {
                verdict = '🚨 CSRF CRITICAL — Sensitive form has NO anti-CSRF token';
                severity = 'CRITICAL';
            }

            findings.csrf.push({
                action,
                method,
                formId,
                inputCount,
                severity,
                verdict,
                reason: 'No CSRF token (hidden input, meta tag, or JS variable) detected',
                sensitive: isSensitiveAction || hasSensitiveFields,
                note: isSensitiveAction ? `⚠️ Sensitive action detected: ${action}` : null
            });
        } else {
            // ===== TOKEN FOUND — CHECK QUALITY =====
            if (tokenValue && tokenValue !== '(dynamic)') {
                allTokenValues.push(tokenValue);

                // === BASIC CHECKS ===
                // Check token length (short tokens are weak)
                if (tokenValue.length < 16) {
                    tokenIssues.push(`Too short (${tokenValue.length} chars, need ≥16)`);
                }

                // Check token entropy (all same chars, sequential, or simple patterns)
                if (/^[0-9]+$/.test(tokenValue)) {
                    tokenIssues.push('Numeric only — predictable');
                }
                if (/^(.)\1+$/.test(tokenValue)) {
                    tokenIssues.push('All identical characters — zero entropy');
                }
                if (/^(0123|1234|abcd|test|demo|sample|csrf)/i.test(tokenValue)) {
                    tokenIssues.push('Common/predictable pattern detected');
                }

                // Check if token looks like a timestamp
                if (/^1[0-9]{9,12}$/.test(tokenValue)) {
                    tokenIssues.push('Appears to be a timestamp — predictable');
                }

                // Check for empty or placeholder tokens
                if (tokenValue.trim() === '' || tokenValue === 'null' || tokenValue === 'undefined' || tokenValue === '0') {
                    tokenIssues.push('Empty/null token value');
                }

                // Check for base64 with very low entropy
                const uniqueChars = new Set(tokenValue.split('')).size;
                if (tokenValue.length > 10 && uniqueChars < 5) {
                    tokenIssues.push(`Very low entropy (only ${uniqueChars} unique chars)`);
                }

                // === ADVANCED CHECKS (v3.6.5) ===

                // 1. Shannon Entropy calculation for better randomness detection
                const entropy = calculateShannonEntropy(tokenValue);
                if (entropy < 3.0 && tokenValue.length >= 16) {
                    tokenIssues.push(`Low Shannon entropy (${entropy.toFixed(2)} bits) — weak randomness`);
                }

                // 2. MD5/SHA hash pattern detection (32/40/64 hex chars)
                if (/^[a-f0-9]{32}$/i.test(tokenValue)) {
                    tokenIssues.push('Appears to be MD5 hash — check if predictable input');
                }
                if (/^[a-f0-9]{40}$/i.test(tokenValue)) {
                    tokenIssues.push('Appears to be SHA-1 hash — check if predictable input');
                }
                if (/^[a-f0-9]{64}$/i.test(tokenValue)) {
                    tokenIssues.push('Appears to be SHA-256 hash — check if predictable input');
                }

                // 3. User ID / Session substring detection
                const urlParams = new URLSearchParams(window.location.search);
                const userId = urlParams.get('user_id') || urlParams.get('uid') || urlParams.get('id');
                if (userId && tokenValue.includes(userId)) {
                    tokenIssues.push('Token contains user ID — predictable per-user');
                }

                // 4. Sequential/Incremental token detection
                if (/^[0-9a-f]+$/i.test(tokenValue)) {
                    const numVal = parseInt(tokenValue, 16);
                    if (!isNaN(numVal) && numVal > 0 && numVal < 1000000) {
                        tokenIssues.push('Low numeric value — possibly sequential');
                    }
                }

                // 5. Double Submit Cookie pattern detection
                if (cookieValues.some(cv => cv === tokenValue || tokenValue.includes(cv) || cv.includes(tokenValue))) {
                    tokenIssues.push('Token matches cookie value — Double Submit Cookie (check cookie attributes)');
                }

                // 6. Base64 decoded analysis
                try {
                    const decoded = atob(tokenValue);
                    if (/^[0-9]+$/.test(decoded)) {
                        tokenIssues.push('Base64 decodes to numeric — predictable');
                    }
                    if (/^(user|admin|guest|test)/i.test(decoded)) {
                        tokenIssues.push('Base64 decodes to common string — predictable');
                    }
                    // Check if decoded is a timestamp
                    if (/^1[0-9]{9,12}$/.test(decoded)) {
                        tokenIssues.push('Base64 decodes to timestamp — predictable');
                    }
                } catch (e) { /* not base64 */ }

                // 7. JWT detection (not a proper CSRF token)
                if (/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(tokenValue)) {
                    tokenIssues.push('JWT used as CSRF token — may be replayable across sessions');
                }

                // 8. Weak character set (only lowercase or only uppercase)
                if (tokenValue.length >= 16 && /^[a-z]+$/.test(tokenValue)) {
                    tokenIssues.push('Lowercase only — reduced keyspace');
                }
                if (tokenValue.length >= 16 && /^[A-Z]+$/.test(tokenValue)) {
                    tokenIssues.push('Uppercase only — reduced keyspace');
                }
                if (tokenValue.length >= 16 && /^[a-zA-Z]+$/.test(tokenValue)) {
                    tokenIssues.push('Letters only — no numbers/symbols, reduced keyspace');
                }
            }

            if (tokenIssues.length > 0) {
                // ===== WEAK TOKEN =====
                findings.csrf.push({
                    action,
                    method,
                    formId,
                    inputCount,
                    severity: 'MEDIUM',
                    verdict: '⚠️ CSRF POSSIBLE — Weak token detected',
                    reason: tokenIssues.join('; '),
                    tokenSource,
                    tokenPreview: tokenValue.substring(0, 20) + (tokenValue.length > 20 ? '...' : ''),
                    sensitive: isSensitiveAction || hasSensitiveFields,
                    note: tokenIssues.join(' | ')
                });
            } else {
                // ===== TOKEN LOOKS OK — report as protected =====
                findings.csrf.push({
                    action,
                    method,
                    formId,
                    inputCount,
                    severity: 'OK',
                    verdict: '✅ CSRF Protected',
                    reason: `Token found via ${tokenSource}`,
                    tokenSource,
                    tokenPreview: tokenValue.substring(0, 10) + '***',
                    sensitive: isSensitiveAction || hasSensitiveFields
                });
            }
        }

        // === FORM-LEVEL VULNERABILITY CHECKS ===

        // Check for token in URL (Referer leakage)
        if (action.includes('csrf') || action.includes('token') || action.includes('_token')) {
            const urlMatch = action.match(/[?&](csrf|token|_token|xsrf)[^&]*/i);
            if (urlMatch) {
                findings.csrf.push({
                    action,
                    method,
                    formId,
                    inputCount,
                    severity: 'MEDIUM',
                    verdict: '⚠️ CSRF Token in URL — Referer Leakage Risk',
                    reason: 'Token in URL query parameter may leak via Referer header to external sites',
                    note: 'Move token to POST body or custom header'
                });
            }
        }

        // Check for formaction/formmethod hijacking
        const buttonsWithFormaction = form.querySelectorAll('button[formaction], input[formaction]');
        if (buttonsWithFormaction.length > 0) {
            findings.csrf.push({
                action,
                method,
                formId,
                inputCount,
                severity: 'LOW',
                verdict: '⚠️ Form has formaction override buttons',
                reason: `${buttonsWithFormaction.length} button(s) can override form action — verify CSRF protection on all targets`,
                note: 'Attacker-controlled formaction could bypass CSRF checks'
            });
        }

        // Check for autocomplete on sensitive forms
        const autocomplete = form.getAttribute('autocomplete');
        if (hasSensitiveFields && autocomplete !== 'off') {
            findings.csrf.push({
                action,
                method,
                formId,
                inputCount,
                severity: 'INFO',
                verdict: '💡 Sensitive form without autocomplete="off"',
                reason: 'Sensitive data may be cached by browser autocomplete',
                note: 'Consider adding autocomplete="off" for sensitive forms'
            });
        }

        // Check for enctype that could enable JSON CSRF
        const enctype = form.getAttribute('enctype');
        if (enctype === 'text/plain') {
            findings.csrf.push({
                action,
                method,
                formId,
                inputCount,
                severity: 'MEDIUM',
                verdict: '⚠️ Form uses text/plain enctype — JSON CSRF possible',
                reason: 'text/plain enctype can be used to craft JSON payloads for CSRF attacks',
                note: 'If endpoint accepts JSON, verify Content-Type validation server-side'
            });
        }
    });

    // Check for duplicate/static tokens across forms (sign of no server-side rotation)
    if (allTokenValues.length > 1) {
        const uniqueTokens = new Set(allTokenValues);
        if (uniqueTokens.size === 1) {
            findings.csrf.push({
                action: '(all forms)',
                method: 'ALL',
                formId: 'global',
                inputCount: 0,
                severity: 'MEDIUM',
                verdict: '⚠️ Static CSRF Token — Same token across all forms',
                reason: `All ${allTokenValues.length} forms share the same token — may not be rotated per-request`,
                note: 'Static tokens are vulnerable to token fixation attacks'
            });
        }
    }

    // Check if AJAX requests lack CSRF headers (intercept prototype)
    checkAjaxCSRF(findings);

    // Check for forms using GET for sensitive actions
    document.querySelectorAll('form').forEach(form => {
        const method = (form.getAttribute('method') || 'GET').toUpperCase();
        const action = (form.getAttribute('action') || '').toLowerCase();
        if (method === 'GET' && /login|password|delete|transfer|payment|admin/i.test(action)) {
            findings.csrf.push({
                action: form.getAttribute('action') || window.location.pathname,
                method: 'GET',
                formId: form.getAttribute('id') || 'unnamed',
                inputCount: form.querySelectorAll('input').length,
                severity: 'MEDIUM',
                verdict: '⚠️ Sensitive action using GET method',
                reason: 'GET requests are susceptible to CSRF via img/link tags and browser history exposure',
                note: 'Should use POST with anti-CSRF token'
            });
        }
    });

    // Check for clickjacking protection (X-Frame-Options / CSP frame-ancestors)
    checkClickjackingCSRF(findings);
}

// Shannon entropy calculation for token randomness analysis
function calculateShannonEntropy(str) {
    const freq = {};
    for (const char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// Check for clickjacking which can enable CSRF-like attacks
function checkClickjackingCSRF(findings) {
    // Check if page can be framed (enables click-based CSRF)
    const hasFrameProtection = document.querySelector('meta[http-equiv="X-Frame-Options"]');

    // Check for frame-busting scripts
    let hasFrameBuster = false;
    try {
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(s => {
            if (/top\s*!==?\s*self|top\.location|parent\.frames/i.test(s.textContent)) {
                hasFrameBuster = true;
            }
        });
    } catch (e) { /* ignore */ }

    // If no frame protection and sensitive forms exist
    const sensitiveForms = document.querySelectorAll('form[action*="login"], form[action*="password"], form[action*="transfer"], form[action*="payment"], form[action*="delete"]');
    if (!hasFrameProtection && !hasFrameBuster && sensitiveForms.length > 0) {
        findings.csrf.push({
            action: '(page-level)',
            method: 'FRAME',
            formId: 'clickjacking',
            inputCount: sensitiveForms.length,
            severity: 'MEDIUM',
            verdict: '⚠️ Clickjacking possible — No frame protection detected',
            reason: 'Page with sensitive forms can be framed, enabling click-based CSRF attacks',
            note: 'Add X-Frame-Options or CSP frame-ancestors header'
        });
    }
}

// Intercept XHR/fetch to see if they carry CSRF headers
function checkAjaxCSRF(findings) {
    try {
        const scriptTags = document.querySelectorAll('script:not([src])');
        let hasAjaxCSRFSetup = false;

        scriptTags.forEach(s => {
            const text = s.textContent;
            if (/axios\.defaults\.headers.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/\$\.ajaxSetup.*headers.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/beforeSend.*setRequestHeader.*csrf/i.test(text)) hasAjaxCSRFSetup = true;
            if (/x-csrf-token|x-xsrf-token/i.test(text)) hasAjaxCSRFSetup = true;
        });

        if (!hasAjaxCSRFSetup && document.querySelectorAll('form[method="POST"]').length === 0) {
            const xhrScripts = document.querySelectorAll('script[src*="axios"], script[src*="jquery"], script[src*="fetch"]');
            const frameworkScripts = document.querySelectorAll('script[src*="react"], script[src*="angular"], script[src*="vue"]');
            if (xhrScripts.length > 0 || frameworkScripts.length > 0) {
                findings.csrf.push({
                    action: '(SPA AJAX calls)',
                    method: 'XHR/FETCH',
                    formId: 'n/a',
                    inputCount: 0,
                    severity: 'MEDIUM',
                    verdict: '⚠️ CSRF POSSIBLE — SPA without visible CSRF protection',
                    reason: 'SPA framework detected with AJAX library but no visible CSRF header configuration',
                    note: 'Check if custom headers or cookies are used for CSRF protection'
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
function injectCanaries() {
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
        const htmlSource = document.documentElement.outerHTML.toLowerCase();

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

// ---- Subresource Integrity (SRI) Scanner (Enhanced v3.6) ----
function scanSRI(findings) {
    const currentOrigin = window.location.origin;

    // Known CDN domains that should have SRI
    const knownCDNs = [
        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
        'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
        'maxcdn.bootstrapcdn.com', 'cdn.bootcdn.net', 'cdn.staticfile.org',
        'lib.baomitu.com', 'ajax.aspnetcdn.com', 'cdn.rawgit.com',
        'rawcdn.githack.com', 'gitcdn.xyz', 'cdn.skypack.dev',
        'esm.sh', 'esm.run', 'ga.jspm.io', 'fonts.googleapis.com',
        'use.fontawesome.com', 'kit.fontawesome.com', 'cdn.tailwindcss.com',
        'cdn.ckeditor.com', 'cdn.tiny.cloud', 'cdn.quilljs.com'
    ];

    // Helper to check if integrity hash is weak
    const isWeakIntegrity = (integrity) => {
        if (!integrity) return false;
        // SHA-256 is weaker than SHA-384/SHA-512
        return integrity.startsWith('sha256-') && !integrity.includes('sha384-') && !integrity.includes('sha512-');
    };

    // Check <script> tags
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
        const src = script.getAttribute('src');
        if (!src) return;

        try {
            const url = new URL(src, window.location.href);
            const isSameOrigin = url.origin === currentOrigin;
            const isKnownCDN = knownCDNs.some(cdn => url.hostname.includes(cdn));
            const hasIntegrity = script.hasAttribute('integrity');
            const integrityValue = script.getAttribute('integrity') || '';
            const hasCrossorigin = script.hasAttribute('crossorigin');
            const isModule = script.getAttribute('type') === 'module';

            // Check for crossorigin without integrity (suspicious)
            if (!isSameOrigin && hasCrossorigin && !hasIntegrity) {
                findings.sri_issues.push({
                    type: 'crossorigin-no-integrity',
                    url: url.href,
                    hostname: url.hostname,
                    hasIntegrity: false,
                    hasCrossorigin: true,
                    isKnownCDN: isKnownCDN,
                    severity: 'HIGH',
                    verdict: '🚨 crossorigin attribute WITHOUT integrity — SRI was likely removed or forgotten!',
                    recommendation: 'Add integrity hash or remove crossorigin if SRI not needed'
                });
                return; // Don't double-report
            }

            // Check for weak integrity hash
            if (hasIntegrity && isWeakIntegrity(integrityValue)) {
                findings.sri_issues.push({
                    type: 'weak-integrity',
                    url: url.href,
                    hostname: url.hostname,
                    hasIntegrity: true,
                    hasCrossorigin: hasCrossorigin,
                    isKnownCDN: isKnownCDN,
                    severity: 'LOW',
                    verdict: '⚠️ Using SHA-256 integrity — SHA-384 or SHA-512 recommended',
                    recommendation: 'Upgrade to sha384-... or sha512-... for stronger integrity'
                });
            }

            // Only flag 3rd party scripts without SRI
            if (!isSameOrigin && !hasIntegrity) {
                let severity = 'MEDIUM';
                let verdict = '⚠️ 3rd party script without SRI';

                if (isKnownCDN) {
                    severity = 'HIGH';
                    verdict = '🚨 CDN script without integrity hash — supply chain risk!';
                }

                // ES modules are higher risk
                if (isModule) {
                    severity = 'HIGH';
                    verdict = '🚨 ES Module from 3rd party without SRI — can import more code!';
                }

                // Check for dangerous patterns
                const isDynamic = /\?|&|{{|%7B%7B/.test(src);
                if (isDynamic) {
                    severity = 'HIGH';
                    verdict = '🚨 Dynamic 3rd party script URL without SRI';
                }

                findings.sri_issues.push({
                    type: isModule ? 'module' : 'script',
                    url: url.href,
                    hostname: url.hostname,
                    hasIntegrity: false,
                    hasCrossorigin: hasCrossorigin,
                    isKnownCDN: isKnownCDN,
                    severity: severity,
                    verdict: verdict,
                    recommendation: 'Add integrity="sha384-..." and crossorigin="anonymous"'
                });
            }
        } catch (e) { /* invalid URL */ }
    });

    // Check <link rel="stylesheet"> tags
    const stylesheets = document.querySelectorAll('link[rel="stylesheet"][href]');
    stylesheets.forEach(link => {
        const href = link.getAttribute('href');
        if (!href) return;

        try {
            const url = new URL(href, window.location.href);
            const isSameOrigin = url.origin === currentOrigin;
            const isKnownCDN = knownCDNs.some(cdn => url.hostname.includes(cdn));
            const hasIntegrity = link.hasAttribute('integrity');

            if (!isSameOrigin && !hasIntegrity) {
                let severity = 'LOW';
                let verdict = '⚠️ 3rd party stylesheet without SRI';

                if (isKnownCDN) {
                    severity = 'MEDIUM';
                    verdict = '⚠️ CDN stylesheet without integrity hash';
                }

                findings.sri_issues.push({
                    type: 'stylesheet',
                    url: url.href,
                    hostname: url.hostname,
                    hasIntegrity: false,
                    hasCrossorigin: link.hasAttribute('crossorigin'),
                    isKnownCDN: isKnownCDN,
                    severity: severity,
                    verdict: verdict,
                    recommendation: 'Add integrity="sha384-..." and crossorigin="anonymous"'
                });
            }
        } catch (e) { /* invalid URL */ }
    });

    // Check <link rel="preload/prefetch"> - often overlooked!
    const preloads = document.querySelectorAll('link[rel="preload"][href], link[rel="prefetch"][href], link[rel="modulepreload"][href]');
    preloads.forEach(link => {
        const href = link.getAttribute('href');
        const asType = link.getAttribute('as');
        if (!href) return;

        try {
            const url = new URL(href, window.location.href);
            const isSameOrigin = url.origin === currentOrigin;
            const hasIntegrity = link.hasAttribute('integrity');
            const relType = link.getAttribute('rel');

            // Preloaded scripts/styles from 3rd party should have SRI
            if (!isSameOrigin && !hasIntegrity && (asType === 'script' || asType === 'style' || relType === 'modulepreload')) {
                findings.sri_issues.push({
                    type: 'preload',
                    url: url.href,
                    hostname: url.hostname,
                    hasIntegrity: false,
                    hasCrossorigin: link.hasAttribute('crossorigin'),
                    isKnownCDN: false,
                    severity: 'MEDIUM',
                    verdict: `⚠️ Preloaded ${asType || 'module'} from 3rd party without SRI`,
                    recommendation: 'Add integrity attribute to preload/prefetch links'
                });
            }
        } catch (e) { /* invalid URL */ }
    });

    // Check 3rd party iframes (uncontrolled code execution)
    const iframes = document.querySelectorAll('iframe[src]');
    iframes.forEach(iframe => {
        const src = iframe.getAttribute('src');
        if (!src || src.startsWith('about:') || src.startsWith('javascript:')) return;

        try {
            const url = new URL(src, window.location.href);
            const isSameOrigin = url.origin === currentOrigin;
            const sandbox = iframe.getAttribute('sandbox');

            if (!isSameOrigin) {
                let severity = 'LOW';
                let verdict = '⚠️ 3rd party iframe — runs uncontrolled code';

                // Check if sandbox is too permissive
                if (!sandbox) {
                    severity = 'MEDIUM';
                    verdict = '⚠️ 3rd party iframe WITHOUT sandbox — full access to own origin';
                } else if (sandbox.includes('allow-scripts') && sandbox.includes('allow-same-origin')) {
                    severity = 'MEDIUM';
                    verdict = '⚠️ 3rd party iframe with allow-scripts + allow-same-origin — can escape sandbox!';
                }

                // Known tracking/ad iframes are lower priority
                const isTracker = /googletagmanager|doubleclick|facebook|analytics|ads|pixel|track/i.test(url.hostname);
                if (!isTracker) {
                    findings.sri_issues.push({
                        type: 'iframe',
                        url: url.href,
                        hostname: url.hostname,
                        hasIntegrity: false,
                        hasCrossorigin: false,
                        isKnownCDN: false,
                        severity: severity,
                        verdict: verdict,
                        recommendation: sandbox ? 'Review sandbox permissions' : 'Add sandbox attribute to restrict capabilities'
                    });
                }
            }
        } catch (e) { /* invalid URL */ }
    });

    // Check for inline scripts loading external resources dynamically
    const inlineScripts = document.querySelectorAll('script:not([src])');
    inlineScripts.forEach(script => {
        const code = script.textContent || '';

        // Check for dynamic script loading patterns
        const dynamicLoadPatterns = [
            { pattern: /document\.createElement\s*\(\s*['"]script['"]\s*\)/gi, type: 'createElement' },
            { pattern: /\.src\s*=\s*['"`][^'"`]*https?:\/\//gi, type: 'src-assignment' },
            { pattern: /new\s+Function\s*\(/gi, type: 'new-Function' },
            { pattern: /import\s*\(\s*['"`]https?:\/\//gi, type: 'dynamic-import' },
            { pattern: /new\s+Worker\s*\(\s*['"`]https?:\/\//gi, type: 'web-worker' },
            { pattern: /new\s+SharedWorker\s*\(\s*['"`]https?:\/\//gi, type: 'shared-worker' },
            { pattern: /navigator\.serviceWorker\.register\s*\(\s*['"`]https?:\/\//gi, type: 'service-worker' }
        ];

        const foundPatterns = new Set();
        dynamicLoadPatterns.forEach(({ pattern, type }) => {
            if (pattern.test(code) && !foundPatterns.has(type)) {
                foundPatterns.add(type);

                let severity = 'MEDIUM';
                let verdict = '⚠️ Dynamic script loading detected — verify SRI is applied';

                if (type === 'service-worker') {
                    severity = 'HIGH';
                    verdict = '🚨 3rd party Service Worker registration — persistent code execution!';
                } else if (type === 'web-worker' || type === 'shared-worker') {
                    severity = 'HIGH';
                    verdict = '🚨 3rd party Worker script — runs in separate thread without SRI support';
                }

                findings.sri_issues.push({
                    type: `dynamic-${type}`,
                    url: `(${type} detected in inline script)`,
                    hostname: 'inline',
                    hasIntegrity: false,
                    hasCrossorigin: false,
                    isKnownCDN: false,
                    severity: severity,
                    verdict: verdict,
                    recommendation: type.includes('worker') ? 'Workers should be same-origin' : 'Ensure dynamically loaded scripts use integrity checks',
                    snippet: code.substring(0, 100) + '...'
                });
            }
        });
    });

    // Check for importmap (ES module imports mapping)
    const importMaps = document.querySelectorAll('script[type="importmap"]');
    importMaps.forEach(script => {
        try {
            const mapContent = JSON.parse(script.textContent || '{}');
            const imports = mapContent.imports || {};

            Object.entries(imports).forEach(([name, url]) => {
                if (typeof url === 'string' && url.startsWith('http')) {
                    try {
                        const parsedUrl = new URL(url);
                        if (parsedUrl.origin !== currentOrigin) {
                            findings.sri_issues.push({
                                type: 'importmap',
                                url: url,
                                hostname: parsedUrl.hostname,
                                hasIntegrity: false,
                                hasCrossorigin: false,
                                isKnownCDN: false,
                                severity: 'HIGH',
                                verdict: `🚨 Import map points "${name}" to 3rd party — no integrity possible!`,
                                recommendation: 'Use same-origin modules or bundler-based imports with SRI'
                            });
                        }
                    } catch (e) { /* invalid URL */ }
                }
            });
        } catch (e) { /* invalid JSON */ }
    });

    // Check stylesheets for @import (CSS can load more CSS)
    const styleElements = document.querySelectorAll('style');
    styleElements.forEach(style => {
        const cssText = style.textContent || '';
        const importMatches = cssText.match(/@import\s+(?:url\s*\(\s*)?['"]?(https?:\/\/[^'"\s)]+)/gi);

        if (importMatches) {
            importMatches.forEach(match => {
                const urlMatch = match.match(/https?:\/\/[^'"\s)]+/i);
                if (urlMatch) {
                    try {
                        const url = new URL(urlMatch[0]);
                        findings.sri_issues.push({
                            type: 'css-import',
                            url: url.href,
                            hostname: url.hostname,
                            hasIntegrity: false,
                            hasCrossorigin: false,
                            isKnownCDN: false,
                            severity: 'MEDIUM',
                            verdict: '⚠️ CSS @import loads 3rd party stylesheet — no SRI for @import',
                            recommendation: 'Use <link> tags with integrity instead of @import'
                        });
                    } catch (e) { /* invalid URL */ }
                }
            });
        }
    });
}

// ---- Host Header Injection Scanner (v3.6.5) ----
function scanHostHeaderInjection(findings) {
    const currentHost = window.location.hostname;
    const currentOrigin = window.location.origin;
    const pathname = window.location.pathname.toLowerCase();

    // Detect if this is a password reset or sensitive page
    const isPasswordResetPage = /reset|forgot|recover|password|pwd|token|verify|confirm|activate|invitation/i.test(pathname) ||
        /reset|forgot|recover|password/i.test(document.title) ||
        document.querySelector('input[type="password"], input[name*="password"], input[name*="pwd"], input[placeholder*="password"]');

    const isHomePage = pathname === '/' || pathname === '/index.html' || pathname === '/index.php' || pathname === '/home';

    const isLoginPage = /login|signin|sign-in|auth|authenticate|sso/i.test(pathname) ||
        document.querySelector('form[action*="login"], form[action*="signin"], form[action*="auth"]');

    const isRegistrationPage = /register|signup|sign-up|create-account|join/i.test(pathname);

    // Check various elements for Host Header Injection indicators

    // 1. Check meta tags with absolute URLs
    const metaTags = document.querySelectorAll('meta[property="og:url"], meta[name="canonical"], link[rel="canonical"], meta[property="og:image"]');
    metaTags.forEach(tag => {
        const content = tag.getAttribute('content') || tag.getAttribute('href');
        if (content && content.includes(currentHost)) {
            findings.host_header.push({
                type: 'meta-tag',
                element: tag.outerHTML.substring(0, 150),
                url: content,
                pageType: isPasswordResetPage ? 'Password Reset Page' : isHomePage ? 'Home Page' : 'Other',
                severity: 'INFO',
                verdict: '💡 Canonical/OG URL contains hostname — test for Host Header Injection',
                reason: 'Meta tags with absolute URLs may reflect Host header value',
                testPayload: `Host: evil.com\\r\\nX-Forwarded-Host: evil.com`,
                note: 'Send request with modified Host header and check if URL changes'
            });
        }
    });

    // 2. Check base href tag
    const baseTag = document.querySelector('base[href]');
    if (baseTag) {
        const baseHref = baseTag.getAttribute('href');
        if (baseHref && (baseHref.includes(currentHost) || baseHref.startsWith('/'))) {
            findings.host_header.push({
                type: 'base-tag',
                element: baseTag.outerHTML,
                url: baseHref,
                pageType: isPasswordResetPage ? 'Password Reset Page' : isHomePage ? 'Home Page' : 'Other',
                severity: 'MEDIUM',
                verdict: '⚠️ <base href> tag found — potential Host Header Injection target',
                reason: 'Base tag can affect all relative URLs on page if Host header is reflected',
                testPayload: `Host: evil.com`,
                note: 'If base href reflects Host header, all links/forms become attackable'
            });
        }
    }

    // 3. Check password reset forms specifically
    if (isPasswordResetPage) {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const action = form.getAttribute('action') || '';

            // Check if form has email/username field (typical for password reset)
            const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"], input[placeholder*="email"]');

            if (hasEmailField) {
                findings.host_header.push({
                    type: 'password-reset-form',
                    element: `<form action="${action}">`,
                    url: action || window.location.href,
                    pageType: 'Password Reset Page',
                    severity: 'HIGH',
                    verdict: '🚨 Password Reset Form — HIGH PRIORITY Host Header Injection target!',
                    reason: 'Password reset links often use Host header to generate reset URLs sent via email',
                    testPayload: `Host: evil.com\\r\\nX-Forwarded-Host: evil.com\\r\\nX-Forwarded-Server: evil.com`,
                    note: 'Submit form with modified Host header — check if reset email contains attacker domain',
                    impactExample: 'Attacker triggers reset → victim clicks link → token sent to attacker domain'
                });
            }
        });

        // Check for hidden token fields that might be in reset links
        const tokenInputs = document.querySelectorAll('input[name*="token"], input[name*="code"], input[name*="key"], input[name*="hash"]');
        if (tokenInputs.length > 0) {
            findings.host_header.push({
                type: 'reset-token-present',
                element: `Found ${tokenInputs.length} token field(s)`,
                url: window.location.href,
                pageType: 'Password Reset Page',
                severity: 'INFO',
                verdict: '💡 Reset token fields detected — verify token delivery mechanism',
                reason: 'Tokens in reset flow may be vulnerable to Host Header attacks during link generation',
                testPayload: `X-Forwarded-Host: evil.com`,
                note: 'Check Burp/proxy for how reset links are constructed'
            });
        }
    }

    // 4. Check login/registration forms (for account takeover chains)
    if (isLoginPage || isRegistrationPage) {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const action = form.getAttribute('action') || '';
            findings.host_header.push({
                type: isLoginPage ? 'login-form' : 'registration-form',
                element: `<form action="${action}">`,
                url: action || window.location.href,
                pageType: isLoginPage ? 'Login Page' : 'Registration Page',
                severity: 'MEDIUM',
                verdict: `⚠️ ${isLoginPage ? 'Login' : 'Registration'} Form — test Host Header for redirect poisoning`,
                reason: 'Post-auth redirects often use Host header for callback URLs',
                testPayload: `Host: evil.com\\r\\nX-Forwarded-Host: evil.com`,
                note: 'Check if post-login redirect or confirmation emails reflect Host header'
            });
        });
    }

    // 5. Check for email-related forms (contact, invite, share)
    const emailForms = document.querySelectorAll('form[action*="mail"], form[action*="invite"], form[action*="share"], form[action*="send"], form[action*="contact"]');
    emailForms.forEach(form => {
        const action = form.getAttribute('action') || '';
        findings.host_header.push({
            type: 'email-form',
            element: `<form action="${action}">`,
            url: action || window.location.href,
            pageType: 'Email/Invite Form',
            severity: 'MEDIUM',
            verdict: '⚠️ Email/Invite Form — links in emails may reflect Host header',
            reason: 'Invitation/share links sent via email often use Host header for URL generation',
            testPayload: `X-Forwarded-Host: evil.com`,
            note: 'Submit form with modified headers — check outgoing email for attacker domain'
        });
    });

    // 6. Check for absolute URLs in JavaScript that reference current host
    const inlineScripts = document.querySelectorAll('script:not([src])');
    inlineScripts.forEach(script => {
        const code = script.textContent || '';

        // Look for patterns where host/origin is being used
        const hostPatterns = [
            { pattern: /window\.location\.host/gi, type: 'window.location.host' },
            { pattern: /window\.location\.origin/gi, type: 'window.location.origin' },
            { pattern: /document\.location\.host/gi, type: 'document.location.host' },
            { pattern: new RegExp(`['"\`]https?://${currentHost.replace(/\./g, '\\.')}`, 'gi'), type: 'hardcoded-origin' },
            { pattern: /apiUrl\s*[=:]\s*['"`]/gi, type: 'apiUrl-assignment' },
            { pattern: /baseUrl\s*[=:]\s*['"`]/gi, type: 'baseUrl-assignment' },
            { pattern: /serverUrl\s*[=:]\s*['"`]/gi, type: 'serverUrl-assignment' }
        ];

        hostPatterns.forEach(({ pattern, type }) => {
            if (pattern.test(code)) {
                // Only add one finding per script per pattern type
                const existingFinding = findings.host_header.find(f => f.type === `js-${type}` && f.element.includes(script.textContent.substring(0, 50)));
                if (!existingFinding) {
                    findings.host_header.push({
                        type: `js-${type}`,
                        element: `JS pattern: ${type}`,
                        url: window.location.href,
                        pageType: isPasswordResetPage ? 'Password Reset Page' : isHomePage ? 'Home Page' : 'Other',
                        severity: 'LOW',
                        verdict: `💡 JavaScript uses ${type} — may reflect in dynamic URLs`,
                        reason: 'Client-side URL construction from location object can be affected by Host header if server reflects it',
                        testPayload: `Host: evil.com`,
                        note: 'Check if server-side reflects Host into HTML/JS that client then uses'
                    });
                }
            }
        });
    });

    // 7. Check for redirect-related meta tags
    const refreshMeta = document.querySelector('meta[http-equiv="refresh"]');
    if (refreshMeta) {
        const content = refreshMeta.getAttribute('content') || '';
        if (content.includes('url=')) {
            findings.host_header.push({
                type: 'meta-refresh',
                element: refreshMeta.outerHTML,
                url: content,
                pageType: isPasswordResetPage ? 'Password Reset Page' : 'Other',
                severity: 'MEDIUM',
                verdict: '⚠️ Meta refresh redirect — test Host Header Injection',
                reason: 'Meta refresh URL may be constructed using Host header server-side',
                testPayload: `Host: evil.com`,
                note: 'If redirect URL reflects Host header, open redirect via HHI is possible'
            });
        }
    }

    // 8. Check for common Host Header injection headers in link generation hints
    const links = document.querySelectorAll('a[href]');
    let absoluteLinksToSelf = 0;
    links.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.includes(currentOrigin)) {
            absoluteLinksToSelf++;
        }
    });

    if (absoluteLinksToSelf > 3) {
        findings.host_header.push({
            type: 'absolute-links',
            element: `${absoluteLinksToSelf} absolute links to current origin`,
            url: currentOrigin,
            pageType: isPasswordResetPage ? 'Password Reset Page' : isHomePage ? 'Home Page' : 'Other',
            severity: 'LOW',
            verdict: '💡 Multiple absolute URLs — page may generate URLs from Host header',
            reason: 'Absolute URLs are often constructed using Host header server-side',
            testPayload: `Host: evil.com\\r\\nX-Forwarded-Host: evil.com\\r\\nX-Host: evil.com`,
            note: 'Test with Burp: change Host header and look for reflection in response'
        });
    }

    // 9. Common headers to test (provide as reference)
    if (isPasswordResetPage || isHomePage) {
        findings.host_header.push({
            type: 'test-headers-reference',
            element: 'Reference: Headers to test',
            url: window.location.href,
            pageType: isPasswordResetPage ? 'Password Reset Page' : 'Home Page',
            severity: 'INFO',
            verdict: '📋 Headers to test for Host Header Injection:',
            reason: 'Different frameworks/proxies respect different headers',
            testPayload: [
                'Host: evil.com',
                'X-Forwarded-Host: evil.com',
                'X-Host: evil.com',
                'X-Forwarded-Server: evil.com',
                'X-HTTP-Host-Override: evil.com',
                'X-Original-URL: /path',
                'X-Rewrite-URL: /path',
                'Forwarded: host=evil.com'
            ].join('\\n'),
            note: 'Try each header individually and in combination with original Host'
        });
    }
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

// ---- Source Map Detector & Downloader (v3.3 Enhanced) ----
async function scanSourceMaps(findings) {
    const sourceMappingRegex = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/gi;
    const cssSourceMappingRegex = /\/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*\//gi;
    const seenMapUrls = new Set();

    // Helper: resolve map URL relative to base URL
    const resolveMapUrl = (mapRef, baseUrl) => {
        try {
            if (!mapRef || mapRef.length < 3) return null;
            if (mapRef.startsWith('data:')) return { type: 'inline', data: mapRef };
            return { type: 'url', url: new URL(mapRef, baseUrl).href };
        } catch (e) {
            return null;
        }
    };

    // Helper: validate map URL accessibility
    const validateMap = async (mapUrl) => {
        try {
            const resp = await fetch(mapUrl, { method: 'HEAD' });
            return {
                accessible: resp.ok,
                status: resp.status,
                size: resp.headers.get('content-length') ? parseInt(resp.headers.get('content-length')) : null,
                contentType: resp.headers.get('content-type') || 'unknown',
                lastModified: resp.headers.get('last-modified') || null
            };
        } catch (e) {
            return { accessible: false, status: 0, size: null, contentType: 'unknown', lastModified: null };
        }
    };

    // Helper: analyze map content to detect framework + source count
    const analyzeMapContent = async (mapUrl) => {
        try {
            const resp = await fetch(mapUrl);
            if (!resp.ok) return null;
            const text = await resp.text();
            if (text.length > 50 * 1024 * 1024) return { sourceCount: '?', framework: 'unknown', totalSize: text.length };

            try {
                const mapData = JSON.parse(text);
                const sources = mapData.sources || [];
                const sourceCount = sources.length;

                // Detect framework
                let framework = 'unknown';
                const allSources = sources.join(' ').toLowerCase();
                if (allSources.includes('node_modules/react') || allSources.includes('react-dom')) framework = 'React';
                else if (allSources.includes('node_modules/@angular')) framework = 'Angular';
                else if (allSources.includes('node_modules/vue') || allSources.includes('.vue')) framework = 'Vue.js';
                else if (allSources.includes('node_modules/next') || allSources.includes('_next/')) framework = 'Next.js';
                else if (allSources.includes('node_modules/nuxt')) framework = 'Nuxt.js';
                else if (allSources.includes('node_modules/svelte') || allSources.includes('.svelte')) framework = 'Svelte';
                else if (allSources.includes('node_modules/ember')) framework = 'Ember.js';
                else if (allSources.includes('webpack://') || allSources.includes('webpack/')) framework = 'Webpack';
                else if (allSources.includes('node_modules/vite') || allSources.includes('/@vite/')) framework = 'Vite';
                else if (allSources.includes('node_modules/jquery')) framework = 'jQuery';
                else if (allSources.includes('.tsx')) framework = 'TypeScript (TSX)';
                else if (allSources.includes('.ts')) framework = 'TypeScript';

                // Check for embedded sourcesContent (full original source code)
                const hasSourceContent = !!(mapData.sourcesContent && mapData.sourcesContent.length > 0);
                const sourceContentCount = mapData.sourcesContent ? mapData.sourcesContent.filter(s => s && s.length > 0).length : 0;

                // Interesting paths (not node_modules)
                const interestingPaths = sources.filter(s =>
                    !s.includes('node_modules/') &&
                    !s.startsWith('webpack/') &&
                    !s.includes('polyfill') &&
                    (s.endsWith('.js') || s.endsWith('.ts') || s.endsWith('.jsx') || s.endsWith('.tsx') || s.endsWith('.vue') || s.endsWith('.svelte'))
                );

                // Extract npm packages from node_modules paths
                const packageMap = {};
                sources.forEach(s => {
                    // Normalize webpack:// prefixes
                    const normalized = s
                        .replace(/^webpack:\/\/\//i, '')
                        .replace(/^webpack:\/\/[^/]*\//i, '')
                        .replace(/^\.\//g, '');

                    // Match node_modules/package or node_modules/@scope/package
                    const nmMatch = normalized.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/);
                    if (nmMatch) {
                        const pkgName = nmMatch[1];
                        if (!packageMap[pkgName]) {
                            packageMap[pkgName] = { name: pkgName, fileCount: 0, isScoped: pkgName.startsWith('@') };
                        }
                        packageMap[pkgName].fileCount++;
                    }
                });

                const packages = Object.values(packageMap).sort((a, b) => b.fileCount - a.fileCount);

                return {
                    sourceCount,
                    framework,
                    hasSourceContent,
                    sourceContentCount,
                    totalSize: text.length,
                    interestingFiles: interestingPaths.length,
                    sampleSources: interestingPaths.slice(0, 5),
                    packages: packages
                };
            } catch (parseErr) {
                return { sourceCount: 0, framework: 'parse-error', totalSize: text.length };
            }
        } catch (e) {
            return null;
        }
    };

    // Helper: add finding (deduplicated)
    const addFinding = async (jsUrl, mapUrl, source, doAnalyze) => {
        if (seenMapUrls.has(mapUrl)) return;
        seenMapUrls.add(mapUrl);

        const validation = await validateMap(mapUrl);
        let analysis = null;
        if (validation.accessible && doAnalyze) {
            analysis = await analyzeMapContent(mapUrl);
        }

        findings.sourcemaps.push({
            jsUrl,
            mapUrl,
            accessible: validation.accessible,
            status: validation.status,
            size: validation.size,
            contentType: validation.contentType,
            lastModified: validation.lastModified,
            source,
            severity: validation.accessible ? 'HIGH' : 'INFO',
            analysis
        });
    };

    // ============================================
    // 1. Scan external JS scripts
    // ============================================
    const scripts = document.querySelectorAll('script[src]');
    const scriptPromises = Array.from(scripts).map(async (s) => {
        const src = s.src;
        if (!src || src.startsWith('chrome-extension://') || src.startsWith('moz-extension://')) return;

        try {
            const isSameOrigin = src.startsWith(window.location.origin);

            if (isSameOrigin) {
                const resp = await fetch(src);
                if (resp.ok) {
                    // Check X-SourceMap / SourceMap response header
                    const headerMap = resp.headers.get('sourcemap') || resp.headers.get('x-sourcemap');
                    if (headerMap) {
                        const resolved = resolveMapUrl(headerMap, src);
                        if (resolved && resolved.type === 'url') {
                            await addFinding(src, resolved.url, 'SourceMap HTTP header', true);
                        }
                    }

                    const text = await resp.text();
                    let match;
                    sourceMappingRegex.lastIndex = 0;
                    while ((match = sourceMappingRegex.exec(text)) !== null) {
                        const resolved = resolveMapUrl(match[1], src);
                        if (resolved) {
                            if (resolved.type === 'url') {
                                await addFinding(src, resolved.url, 'sourceMappingURL comment', true);
                            } else if (resolved.type === 'inline') {
                                const inlineSize = resolved.data.length;
                                if (!seenMapUrls.has('inline:' + src)) {
                                    seenMapUrls.add('inline:' + src);
                                    findings.sourcemaps.push({
                                        jsUrl: src,
                                        mapUrl: '(inline data: URI)',
                                        accessible: true,
                                        status: 200,
                                        size: Math.round(inlineSize * 0.75),
                                        contentType: 'application/json (inline)',
                                        lastModified: null,
                                        source: 'inline data: URI',
                                        severity: 'MEDIUM',
                                        analysis: null
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Direct .map probe (works cross-origin too)
            const cleanUrl = src.split('?')[0];
            const probeUrls = [cleanUrl + '.map'];
            if (src !== cleanUrl) probeUrls.push(src + '.map');

            for (const probeUrl of probeUrls) {
                if (!seenMapUrls.has(probeUrl)) {
                    const probeValid = await validateMap(probeUrl);
                    if (probeValid.accessible) {
                        await addFinding(src, probeUrl, 'direct .map probe', true);
                        break;
                    }
                }
            }
        } catch (e) { /* ignore CORS / network errors */ }
    });

    await Promise.all(scriptPromises);

    // ============================================
    // 2. Scan CSS stylesheets for source maps
    // ============================================
    const styleSheets = document.querySelectorAll('link[rel="stylesheet"][href]');
    const cssPromises = Array.from(styleSheets).map(async (link) => {
        const href = link.href;
        if (!href || !href.startsWith(window.location.origin)) return;

        try {
            const resp = await fetch(href);
            if (!resp.ok) return;

            const headerMap = resp.headers.get('sourcemap') || resp.headers.get('x-sourcemap');
            if (headerMap) {
                const resolved = resolveMapUrl(headerMap, href);
                if (resolved && resolved.type === 'url') {
                    await addFinding(href, resolved.url, 'CSS SourceMap header', true);
                }
            }

            const text = await resp.text();
            let match;
            cssSourceMappingRegex.lastIndex = 0;
            while ((match = cssSourceMappingRegex.exec(text)) !== null) {
                const resolved = resolveMapUrl(match[1], href);
                if (resolved && resolved.type === 'url') {
                    await addFinding(href, resolved.url, 'CSS sourceMappingURL', true);
                }
            }

            // Direct probe
            const cssMapUrl = href.split('?')[0] + '.map';
            if (!seenMapUrls.has(cssMapUrl)) {
                const probeValid = await validateMap(cssMapUrl);
                if (probeValid.accessible) {
                    await addFinding(href, cssMapUrl, 'CSS .map probe', true);
                }
            }
        } catch (e) { /* ignore */ }
    });

    await Promise.all(cssPromises);

    // ============================================
    // 3. Inline scripts with sourceMappingURL
    // ============================================
    const inlineScripts = document.querySelectorAll('script:not([src])');
    const inlinePromises = Array.from(inlineScripts).map(async (script) => {
        const code = script.textContent;
        if (!code || code.length < 10) return;

        let match;
        sourceMappingRegex.lastIndex = 0;
        while ((match = sourceMappingRegex.exec(code)) !== null) {
            const resolved = resolveMapUrl(match[1], window.location.href);
            if (resolved && resolved.type === 'url') {
                await addFinding('(inline script)', resolved.url, 'inline sourceMappingURL', true);
            }
        }
    });

    await Promise.all(inlinePromises);

    // ============================================
    // 4. Build-tool pattern probing (Webpack, Next.js, Nuxt)
    // ============================================
    try {
        const bodyHTML = document.documentElement.outerHTML;
        const chunkProbes = [];

        // Webpack chunks
        const chunkRegex = /["']([a-zA-Z0-9._\/\-]+\.chunk\.js(?:\?[^"']*)?)['"]/gi;
        let cm;
        while ((cm = chunkRegex.exec(bodyHTML)) !== null) {
            try {
                const absUrl = new URL(cm[1], window.location.href).href;
                const mapUrl = absUrl.split('?')[0] + '.map';
                if (!seenMapUrls.has(mapUrl)) chunkProbes.push(addFinding(absUrl, mapUrl, 'webpack chunk probe', true));
            } catch (e) { }
        }

        // Next.js _next/static
        const nextRegex = /["']((?:\/_next\/static\/[a-zA-Z0-9._\/\-]+)\.js(?:\?[^"']*)?)['"]/gi;
        let nm;
        while ((nm = nextRegex.exec(bodyHTML)) !== null) {
            try {
                const absUrl = new URL(nm[1], window.location.href).href;
                const mapUrl = absUrl.split('?')[0] + '.map';
                if (!seenMapUrls.has(mapUrl)) chunkProbes.push(addFinding(absUrl, mapUrl, 'Next.js .map probe', true));
            } catch (e) { }
        }

        // Nuxt.js _nuxt/
        const nuxtRegex = /["']((?:\/_nuxt\/[a-zA-Z0-9._\/\-]+)\.js(?:\?[^"']*)?)['"]/gi;
        let nux;
        while ((nux = nuxtRegex.exec(bodyHTML)) !== null) {
            try {
                const absUrl = new URL(nux[1], window.location.href).href;
                const mapUrl = absUrl.split('?')[0] + '.map';
                if (!seenMapUrls.has(mapUrl)) chunkProbes.push(addFinding(absUrl, mapUrl, 'Nuxt.js .map probe', true));
            } catch (e) { }
        }

        if (chunkProbes.length > 0) await Promise.all(chunkProbes.slice(0, 15));
    } catch (e) { /* safe */ }

    // ============================================
    // 5. Filter out noise
    // ============================================
    findings.sourcemaps = findings.sourcemaps.filter(sm =>
        sm.accessible || !sm.source.includes('probe')
    );
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
        data.sourcemaps = findings.sourcemaps;
        data.sri_issues = findings.sri_issues;
        data.host_header = findings.host_header;
        data.lastScan = new Date().toISOString();
        data.pageUrl = window.location.href;

        const updateObj = {};
        updateObj[host] = data;
        chrome.storage.local.set(updateObj);
    });
}

// ---- Run on page load ----
scanPage();

// ---- Listen for messages from background/popup ----
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'rescan') {
        scanPage();
        sendResponse({ status: 'done' });
    } else if (request.action === 'fetchSourceMap' && request.url) {
        // Fetch source map from content script context (bypasses CORS for same-origin)
        // Uses chunked transfer for large files to avoid message size limits
        (async () => {
            try {
                console.log('[BountySleuth CS] Fetching source map:', request.url);
                let resp = await fetch(request.url, { credentials: 'include' });
                if (!resp.ok) {
                    resp = await fetch(request.url, { credentials: 'omit' });
                }
                if (!resp.ok) {
                    resp = await fetch(request.url);
                }
                if (!resp.ok) {
                    sendResponse({ error: `HTTP ${resp.status}` });
                    return;
                }
                const text = await resp.text();
                console.log('[BountySleuth CS] Fetched, size:', text.length);
                
                // Chrome message size limit is ~64MB, Firefox is ~50MB
                // Use chunked transfer for files >40MB to be safe
                const CHUNK_SIZE = 40 * 1024 * 1024; // 40MB chunks
                
                if (text.length > CHUNK_SIZE) {
                    console.log('[BountySleuth CS] Large file detected, using chunked transfer');
                    sendResponse({ 
                        chunked: true, 
                        totalSize: text.length,
                        totalChunks: Math.ceil(text.length / CHUNK_SIZE)
                    });
                } else {
                    sendResponse({ text: text, length: text.length });
                }
            } catch (e) {
                console.error('[BountySleuth CS] Fetch error:', e.message);
                sendResponse({ error: e.message });
            }
        })();
        return true; // Keep channel open for async response
    } else if (request.action === 'fetchSourceMapChunk' && request.url && request.chunkIndex !== undefined) {
        // Fetch a specific chunk of a large sourcemap with better error handling
        (async () => {
            try {
                const CHUNK_SIZE = 40 * 1024 * 1024; // 40MB chunks
                const start = request.chunkIndex * CHUNK_SIZE;
                const end = start + CHUNK_SIZE - 1;
                
                console.log('[BountySleuth CS] Fetching chunk', request.chunkIndex, 'range:', start, '-', end);
                
                // Strategy 1: Try Range request first (most efficient)
                let resp = await fetch(request.url, { 
                    credentials: 'include',
                    headers: { 'Range': `bytes=${start}-${end}` }
                });
                
                if (resp.status === 206) {
                    // Partial content supported - perfect!
                    const chunk = await resp.text();
                    console.log('[BountySleuth CS] Chunk', request.chunkIndex, 'size:', chunk.length, '(via Range)');
                    sendResponse({ chunk: chunk, chunkIndex: request.chunkIndex });
                    return;
                }
                
                // Strategy 2: Range not supported, use streaming to avoid loading full file
                console.log('[BountySleuth CS] Range not supported, using streaming approach...');
                
                // Try with credentials
                resp = await fetch(request.url, { credentials: 'include' });
                if (!resp.ok) {
                    // Try without credentials
                    resp = await fetch(request.url, { credentials: 'omit' });
                }
                if (!resp.ok) {
                    // Try default
                    resp = await fetch(request.url);
                }
                
                if (!resp.ok) {
                    throw new Error(`HTTP ${resp.status}`);
                }
                
                // Check content length to avoid loading huge files into memory
                const contentLength = resp.headers.get('content-length');
                if (contentLength && parseInt(contentLength) > 500 * 1024 * 1024) {
                    // File is >500MB and Range not supported - this will be problematic
                    throw new Error(`File too large (${Math.round(parseInt(contentLength) / 1024 / 1024)}MB) and server doesn't support Range requests. Cannot safely chunk.`);
                }
                
                const fullText = await resp.text();
                const chunk = fullText.substring(start, start + CHUNK_SIZE);
                
                if (chunk.length === 0 && start < fullText.length) {
                    throw new Error(`Chunk extraction failed: start=${start}, fullLength=${fullText.length}`);
                }
                
                console.log('[BountySleuth CS] Chunk', request.chunkIndex, 'size:', chunk.length, '(via slice)');
                sendResponse({ chunk: chunk, chunkIndex: request.chunkIndex });
                
            } catch (e) {
                console.error('[BountySleuth CS] Chunk fetch error:', e.message);
                sendResponse({ error: `Chunk ${request.chunkIndex} failed: ${e.message}` });
            }
        })();
        return true;
    }
});
