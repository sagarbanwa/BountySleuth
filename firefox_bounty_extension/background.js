// ============================================================
// BountySleuth v2.0 - Background Script
// WAF Fingerprint / Security Headers / CORS Analysis
// ============================================================

// ---- WAF Signature Database ----
const WAF_SIGNATURES = {
    headers: {
        'cf-ray': 'Cloudflare',
        'cf-cache-status': 'Cloudflare',
        'cf-request-id': 'Cloudflare',
        'x-sucuri-id': 'Sucuri WAF',
        'x-sucuri-cache': 'Sucuri WAF',
        'x-amz-cf-id': 'AWS CloudFront',
        'x-amz-cf-pop': 'AWS CloudFront',
        'x-azure-ref': 'Azure Front Door',
        'x-ms-ref': 'Azure CDN',
        'x-akamai-transformed': 'Akamai',
        'x-akamai-session-info': 'Akamai',
        'x-iinfo': 'Imperva Incapsula',
        'x-cdn': 'Imperva Incapsula',
        'x-fw-type': 'FortiWeb WAF',
        'x-edgeconnect-midmile-rtt': 'Akamai Edge',
        'x-cache': 'CDN Cache (generic)',
        'x-varnish': 'Varnish Cache',
        'x-fastly-request-id': 'Fastly CDN',
        'x-served-by': 'Fastly CDN',
        'x-timer': 'Fastly CDN',
        'x-litespeed-cache': 'LiteSpeed Cache',
        'x-proxy-cache': 'Proxy Cache (generic)'
    },
    serverValues: {
        'cloudflare': 'Cloudflare',
        'sucuri': 'Sucuri',
        'akamaighost': 'Akamai',
        'amazons3': 'Amazon S3',
        'awselb': 'AWS ELB',
        'bigip': 'F5 BIG-IP',
        'barracuda': 'Barracuda WAF',
        'citrix': 'Citrix NetScaler',
        'fortiweb': 'FortiWeb',
        'openresty': 'OpenResty (Nginx+Lua)',
        'litespeed': 'LiteSpeed',
        'envoy': 'Envoy Proxy',
        'kong': 'Kong API Gateway',
        'traefik': 'Traefik Proxy'
    }
};

// ---- Security Headers to Check ----
const SECURITY_HEADERS = {
    'content-security-policy': { name: 'Content-Security-Policy', severity: 'HIGH' },
    'x-frame-options': { name: 'X-Frame-Options', severity: 'MEDIUM' },
    'x-content-type-options': { name: 'X-Content-Type-Options', severity: 'MEDIUM' },
    'strict-transport-security': { name: 'Strict-Transport-Security (HSTS)', severity: 'HIGH' },
    'x-xss-protection': { name: 'X-XSS-Protection', severity: 'LOW' },
    'referrer-policy': { name: 'Referrer-Policy', severity: 'LOW' },
    'permissions-policy': { name: 'Permissions-Policy', severity: 'LOW' },
    'cross-origin-opener-policy': { name: 'Cross-Origin-Opener-Policy', severity: 'LOW' },
    'cross-origin-resource-policy': { name: 'Cross-Origin-Resource-Policy', severity: 'LOW' },
    'cross-origin-embedder-policy': { name: 'Cross-Origin-Embedder-Policy', severity: 'LOW' }
};

// ---- Main Listener ----
chrome.webRequest.onHeadersReceived.addListener(
    function (details) {
        // Now processing main_frame AND xmlhttprequest/fetch (sub_frame)
        const isMain = details.type === 'main_frame';

        try {
            const url = new URL(details.url);
            const host = url.hostname;
            const headers = details.responseHeaders;

            const analysis = {
                wafs: [],
                security_headers_missing: [],
                security_headers_present: [],
                cors: null,
                server_info: []
            };

            const headerMap = {};
            headers.forEach(h => {
                headerMap[h.name.toLowerCase()] = h.value;
            });

            // 1. WAF Detection
            detectWAFs(headerMap, analysis);

            // 2. Security Headers Check (Main Frame only)
            if (isMain) {
                checkSecurityHeaders(headerMap, analysis);
            }

            // 3. CORS Analysis (Check all responses)
            checkCORS(headerMap, analysis, details.url);

            // 4. Server Info Leaks
            checkServerInfo(headerMap, analysis);

            // Save and Sync
            chrome.storage.local.get([host], (result) => {
                const data = result[host] || { wafs: [], security_headers_missing: [], security_headers_present: [], server_info: [], cors_history: [] };

                // Update WAFs (merge)
                const combinedWafs = new Set([...data.wafs, ...analysis.wafs]);
                data.wafs = Array.from(combinedWafs);

                // Update Server Info (merge)
                const combinedServer = new Set([...data.server_info, ...analysis.server_info]);
                data.server_info = Array.from(combinedServer);

                // Security headers (keep main frame latest)
                if (isMain) {
                    data.security_headers_missing = analysis.security_headers_missing;
                    data.security_headers_present = analysis.security_headers_present;
                }

                // CORS History
                if (analysis.cors) {
                    data.cors = analysis.cors; // Latest
                    if (!data.cors_history) data.cors_history = [];
                    if (!data.cors_history.some(c => c.origin === analysis.cors.origin)) {
                        data.cors_history.push({ url: details.url, ...analysis.cors });
                    }
                }

                const updateObj = {};
                updateObj[host] = data;
                chrome.storage.local.set(updateObj, () => {
                    updateBadge(host);
                });
            });

        } catch (e) {
            console.error('BountySleuth background error:', e);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
);

// ---- Badge Management ----
let badgeTimeoutMap = {};

function updateBadge(host) {
    if (badgeTimeoutMap[host]) {
        clearTimeout(badgeTimeoutMap[host]);
    }

    badgeTimeoutMap[host] = setTimeout(() => {
        chrome.storage.local.get([host], (result) => {
            const data = result[host];
            if (!data) return;

            let totalVulns = 0;
            if (data.csrf) totalVulns += data.csrf.length;
            if (data.xss) totalVulns += data.xss.length;
            if (data.reflected_params) totalVulns += data.reflected_params.length;
            if (data.dom_sinks) totalVulns += data.dom_sinks.length;
            if (data.post_messages) totalVulns += data.post_messages.length;
            if (data.leaks) totalVulns += data.leaks.length;
            if (data.cloud_assets) totalVulns += data.cloud_assets.length;
            if (data.cors && data.cors.severity === 'CRITICAL') totalVulns += 1;

            if (totalVulns > 0) {
                chrome.action.setBadgeText({ text: totalVulns.toString() });
                const color = totalVulns > 5 ? '#f85149' : '#d29922'; // Red for high count, Orange otherwise
                chrome.action.setBadgeBackgroundColor({ color: color });
            } else {
                chrome.action.setBadgeText({ text: '' });
            }
        });
    }, 250);
}

// Clear badge when changing tabs
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab && tab.url) {
            try {
                const url = new URL(tab.url);
                updateBadge(url.hostname);
            } catch (e) { chrome.action.setBadgeText({ text: '' }); }
        }
    });
});

// ---- WAF Detection ----
function detectWAFs(headerMap, analysis) {
    const wafs = new Set();

    // Check direct header names
    Object.keys(WAF_SIGNATURES.headers).forEach(headerName => {
        if (headerMap[headerName]) {
            wafs.add(WAF_SIGNATURES.headers[headerName]);
        }
    });

    // Check server value
    const server = (headerMap['server'] || '').toLowerCase();
    if (server) {
        Object.keys(WAF_SIGNATURES.serverValues).forEach(key => {
            if (server.includes(key)) {
                wafs.add(WAF_SIGNATURES.serverValues[key]);
            }
        });
        // Always log the raw server header
        analysis.server_info.push(`Server: ${headerMap['server']}`);
    }

    // Check x-powered-by
    const poweredBy = headerMap['x-powered-by'];
    if (poweredBy) {
        analysis.server_info.push(`X-Powered-By: ${poweredBy}`);
    }

    // Check via header
    const via = headerMap['via'];
    if (via) {
        analysis.server_info.push(`Via: ${via}`);
    }

    analysis.wafs = Array.from(wafs);
}

// ---- Security Headers ----
function checkSecurityHeaders(headerMap, analysis) {
    Object.keys(SECURITY_HEADERS).forEach(headerName => {
        const info = SECURITY_HEADERS[headerName];
        if (headerMap[headerName]) {
            analysis.security_headers_present.push({
                name: info.name,
                value: headerMap[headerName].substring(0, 100),
                severity: 'OK'
            });
        } else {
            analysis.security_headers_missing.push({
                name: info.name,
                severity: info.severity
            });
        }
    });
}

// ---- CORS Analysis ----
function checkCORS(headerMap, analysis, requestUrl) {
    const acao = headerMap['access-control-allow-origin'];
    const acac = headerMap['access-control-allow-credentials'];

    if (acao) {
        const isStar = acao.trim() === '*';
        const allowsCreds = acac && acac.toLowerCase() === 'true';

        let severity = 'INFO';
        let issue = '';

        if (isStar && allowsCreds) {
            severity = 'CRITICAL';
            issue = 'Wildcard (*) origin WITH credentials allowed — full CORS misconfiguration!';
        } else if (isStar) {
            severity = 'MEDIUM';
            issue = 'Wildcard (*) origin allowed (no credentials). May leak data cross-origin.';
        } else if (allowsCreds) {
            severity = 'HIGH';
            issue = `Origin "${acao}" allowed with credentials. Potential reflection at endpoint.`;
        }

        if (issue) {
            analysis.cors = {
                origin: acao,
                credentials: allowsCreds,
                severity: severity,
                issue: issue,
                endpoint: requestUrl
            };
        }
    }
}

// ---- Server Info Leaks ----
function checkServerInfo(headerMap, analysis) {
    // Additional technology fingerprinting
    const techHeaders = ['x-aspnet-version', 'x-aspnetmvc-version', 'x-runtime', 'x-generator', 'x-drupal-cache', 'x-wordpress'];
    techHeaders.forEach(h => {
        if (headerMap[h]) {
            analysis.server_info.push(`${h}: ${headerMap[h]}`);
        }
    });
}
