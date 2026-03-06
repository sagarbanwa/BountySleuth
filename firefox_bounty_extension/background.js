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
                server_info: [],
                cache_issues: []
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

            // 5. Cache Security Analysis
            checkCacheSecurity(headerMap, analysis, details.url, isMain);

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

                // Cache Issues (merge)
                if (analysis.cache_issues && analysis.cache_issues.length > 0) {
                    if (!data.cache_issues) data.cache_issues = [];
                    analysis.cache_issues.forEach(issue => {
                        // Avoid duplicates by URL
                        if (!data.cache_issues.some(c => c.url === issue.url)) {
                            data.cache_issues.push(issue);
                        }
                    });
                    // Keep only last 50 cache issues
                    if (data.cache_issues.length > 50) {
                        data.cache_issues = data.cache_issues.slice(-50);
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

// ---- Cache Security Analysis (Enhanced v3.6) ----
function checkCacheSecurity(headerMap, analysis, requestUrl, isMainFrame) {
    const cacheControl = (headerMap['cache-control'] || '').toLowerCase();
    const vary = (headerMap['vary'] || '').toLowerCase();
    const cdnCacheControl = headerMap['cdn-cache-control'] || headerMap['cloudflare-cdn-cache-control'] || headerMap['surrogate-control'];
    const pragma = (headerMap['pragma'] || '').toLowerCase();
    const xCache = headerMap['x-cache'] || '';
    const cfCacheStatus = headerMap['cf-cache-status'] || '';
    const age = headerMap['age'] || '';
    const etag = headerMap['etag'] || '';
    const lastModified = headerMap['last-modified'] || '';

    // Sensitive URL patterns that should NOT be publicly cached
    const sensitivePatterns = /\/(api|auth|login|logout|register|signup|password|reset|account|profile|admin|dashboard|checkout|payment|order|cart|session|token|user|me|private|internal|settings|billing|subscription|graphql|oauth|callback|webhook)/i;
    const isSensitiveUrl = sensitivePatterns.test(requestUrl);

    // Web Cache Deception patterns (path confusion) - sensitive URL ending with static extension
    const hasPathConfusion = /\/[^\/]+\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf)$/i.test(requestUrl) && isSensitiveUrl;

    // Parse cache-control directives
    const isPublic = cacheControl.includes('public');
    const isPrivate = cacheControl.includes('private');
    const hasNoStore = cacheControl.includes('no-store');
    const hasNoCache = cacheControl.includes('no-cache');
    const hasMustRevalidate = cacheControl.includes('must-revalidate');
    const hasImmutable = cacheControl.includes('immutable');
    const maxAgeMatch = cacheControl.match(/max-age\s*=\s*(\d+)/);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : null;
    const sMaxAgeMatch = cacheControl.match(/s-maxage\s*=\s*(\d+)/);
    const sMaxAge = sMaxAgeMatch ? parseInt(sMaxAgeMatch[1]) : null;

    let issues = [];

    // Check 1: Public caching on sensitive endpoints
    if (isPublic && isSensitiveUrl) {
        issues.push({
            url: requestUrl,
            type: 'public-sensitive',
            severity: 'CRITICAL',
            verdict: '🚨 PUBLIC caching on sensitive endpoint!',
            header: `Cache-Control: ${cacheControl}`,
            recommendation: 'Use Cache-Control: private, no-store for sensitive endpoints'
        });
    }

    // Check 2: Missing no-store on authenticated/sensitive pages
    if (isSensitiveUrl && !hasNoStore && !isPrivate && isMainFrame) {
        const hasAuthHeader = headerMap['authorization'] || headerMap['set-cookie'];
        if (hasAuthHeader || isPublic) {
            issues.push({
                url: requestUrl,
                type: 'missing-no-store',
                severity: 'HIGH',
                verdict: '⚠️ Sensitive endpoint without no-store directive',
                header: cacheControl ? `Cache-Control: ${cacheControl}` : 'No Cache-Control header',
                recommendation: 'Add Cache-Control: no-store to prevent caching of sensitive data'
            });
        }
    }

    // Check 3: Long max-age on dynamic content
    if (maxAge && maxAge > 86400 && isMainFrame) {
        issues.push({
            url: requestUrl,
            type: 'long-cache',
            severity: 'LOW',
            verdict: `⚠️ Long cache duration: ${maxAge} seconds (${Math.round(maxAge / 86400)} days)`,
            header: `Cache-Control: ${cacheControl}`,
            recommendation: 'Consider shorter cache times for dynamic content'
        });
    }

    // Check 4: Vary header missing Authorization for authenticated endpoints
    if (isSensitiveUrl && !vary.includes('authorization') && !hasNoStore) {
        const hasAuthCookie = headerMap['set-cookie'] && /session|auth|token/i.test(headerMap['set-cookie']);
        if (hasAuthCookie) {
            issues.push({
                url: requestUrl,
                type: 'vary-missing-auth',
                severity: 'MEDIUM',
                verdict: '⚠️ Vary header missing Authorization — cached responses may leak between users',
                header: vary ? `Vary: ${vary}` : 'No Vary header',
                recommendation: 'Add Vary: Authorization, Cookie to prevent cache poisoning'
            });
        }
    }

    // Check 5: CDN caching issues
    if (cdnCacheControl && isSensitiveUrl) {
        const cdnPublic = cdnCacheControl.toLowerCase().includes('public');
        if (cdnPublic) {
            issues.push({
                url: requestUrl,
                type: 'cdn-public-sensitive',
                severity: 'HIGH',
                verdict: '🚨 CDN configured to publicly cache sensitive endpoint',
                header: `CDN-Cache-Control: ${cdnCacheControl}`,
                recommendation: 'Configure CDN to bypass cache for authenticated/sensitive routes'
            });
        }
    }

    // Check 6: s-maxage (shared cache) on sensitive endpoints
    if (sMaxAge && sMaxAge > 0 && isSensitiveUrl) {
        issues.push({
            url: requestUrl,
            type: 's-maxage-sensitive',
            severity: 'HIGH',
            verdict: `⚠️ Shared cache (s-maxage=${sMaxAge}) enabled on sensitive endpoint`,
            header: `Cache-Control: ${cacheControl}`,
            recommendation: 'Remove s-maxage or add private directive for sensitive endpoints'
        });
    }

    // Check 7: Web Cache Deception vulnerability pattern
    if (hasPathConfusion && !isPrivate && !hasNoStore) {
        issues.push({
            url: requestUrl,
            type: 'cache-deception',
            severity: 'HIGH',
            verdict: '🚨 Potential Web Cache Deception — sensitive URL with static extension',
            header: `URL ends with static extension on sensitive path`,
            recommendation: 'Ensure Cache-Control: private, no-store on all authenticated responses regardless of URL extension'
        });
    }

    // Check 8: X-Cache HIT on sensitive endpoint (evidence of caching)
    if (isSensitiveUrl && (xCache.toLowerCase().includes('hit') || cfCacheStatus.toLowerCase() === 'hit')) {
        issues.push({
            url: requestUrl,
            type: 'cache-hit-sensitive',
            severity: 'HIGH',
            verdict: '🚨 Cache HIT detected on sensitive endpoint — response IS being cached!',
            header: xCache ? `X-Cache: ${xCache}` : `CF-Cache-Status: ${cfCacheStatus}`,
            recommendation: 'Investigate why sensitive response is being cached. Add no-store directive.'
        });
    }

    // Check 9: Stale content allowed (missing must-revalidate on sensitive)
    if (isSensitiveUrl && maxAge && !hasMustRevalidate && !hasNoStore && !isPrivate) {
        issues.push({
            url: requestUrl,
            type: 'stale-allowed',
            severity: 'MEDIUM',
            verdict: '⚠️ Missing must-revalidate — stale cached content may be served',
            header: `Cache-Control: ${cacheControl}`,
            recommendation: 'Add must-revalidate to force revalidation after max-age expires'
        });
    }

    // Check 10: Immutable on dynamic/sensitive content
    if (hasImmutable && isSensitiveUrl) {
        issues.push({
            url: requestUrl,
            type: 'immutable-sensitive',
            severity: 'MEDIUM',
            verdict: '⚠️ Immutable directive on sensitive/dynamic content',
            header: `Cache-Control: ${cacheControl}`,
            recommendation: 'Remove immutable from sensitive endpoints — only use for truly static assets with versioned URLs'
        });
    }

    // Check 11: ETag/Last-Modified without no-store (cache timing attacks)
    if (isSensitiveUrl && (etag || lastModified) && !hasNoStore) {
        issues.push({
            url: requestUrl,
            type: 'conditional-cache-sensitive',
            severity: 'LOW',
            verdict: '⚠️ ETag/Last-Modified on sensitive endpoint — enables cache-based timing attacks',
            header: etag ? `ETag: ${etag.substring(0, 30)}...` : `Last-Modified: ${lastModified}`,
            recommendation: 'Use no-store for sensitive data to prevent conditional request timing attacks'
        });
    }

    // Check 12: Cache Poisoning via Unkeyed Headers detection
    // Check if dangerous headers are present that could be used for poisoning
    const poisonableHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url', 'x-forwarded-scheme', 'x-forwarded-proto'];
    const variedHeaders = vary.split(',').map(h => h.trim().toLowerCase());

    poisonableHeaders.forEach(header => {
        if (headerMap[header] && !variedHeaders.includes(header) && !hasNoStore && !isPrivate) {
            if (isMainFrame || isSensitiveUrl) {
                issues.push({
                    url: requestUrl,
                    type: 'unkeyed-header',
                    severity: 'HIGH',
                    verdict: `🚨 Potential Cache Poisoning — ${header} present but not in Vary`,
                    header: `${header}: ${headerMap[header]} (not in Vary: ${vary || 'none'})`,
                    recommendation: `Add "${header}" to Vary header or use Cache-Control: private`
                });
            }
        }
    });

    // Check 13: Age header indicates long caching on sensitive
    if (isSensitiveUrl && age && parseInt(age) > 60) {
        issues.push({
            url: requestUrl,
            type: 'aged-cache',
            severity: 'MEDIUM',
            verdict: `⚠️ Cached response is ${age} seconds old — sensitive data may be stale/shared`,
            header: `Age: ${age}`,
            recommendation: 'Sensitive data should not be served from cache with high Age values'
        });
    }

    // Check 14: Pragma: no-cache without Cache-Control: no-store (incomplete)
    if (pragma.includes('no-cache') && !hasNoStore && !hasNoCache && isSensitiveUrl) {
        issues.push({
            url: requestUrl,
            type: 'pragma-incomplete',
            severity: 'LOW',
            verdict: '⚠️ Pragma: no-cache without Cache-Control: no-cache/no-store',
            header: `Pragma: ${pragma}, Cache-Control: ${cacheControl || 'none'}`,
            recommendation: 'Pragma is HTTP/1.0 — also use Cache-Control: no-store for HTTP/1.1 caches'
        });
    }

    // Add all issues to analysis
    issues.forEach(issue => {
        analysis.cache_issues.push(issue);
    });
}

// ---- Source Map Unpacker & ZIP Downloader (v3.4) ----

/**
 * A minimal, dependency-free ZIP writer (Stored format)
 * Reconstructs directory structures from source maps.
 */
class SimpleZipWriter {
    constructor() {
        this.files = [];
    }

    addFile(path, content) {
        const encoder = new TextEncoder();
        const data = typeof content === 'string' ? encoder.encode(content) : new Uint8Array(content);
        this.files.push({
            path: path.replace(/\\/g, '/').replace(/^\/+/, ''),
            data: data,
            time: new Date()
        });
    }

    _dateToDos(date) {
        const y = date.getFullYear();
        if (y < 1980) return 0;
        return ((y - 1980) << 25) | ((date.getMonth() + 1) << 21) | (date.getDate() << 16) |
            (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1);
    }

    toUint8Array() {
        let totalSize = 0;
        const centralDirSize = this.files.reduce((acc, f) => acc + 46 + f.path.length, 0);
        const fileDataSize = this.files.reduce((acc, f) => acc + 30 + f.path.length + f.data.length, 0);
        const buffer = new Uint8Array(fileDataSize + centralDirSize + 22);
        let offset = 0;

        const writeUint16 = (val) => { buffer[offset++] = val & 0xFF; buffer[offset++] = (val >> 8) & 0xFF; };
        const writeUint32 = (val) => {
            buffer[offset++] = val & 0xFF; buffer[offset++] = (val >> 8) & 0xFF;
            buffer[offset++] = (val >> 16) & 0xFF; buffer[offset++] = (val >> 24) & 0xFF;
        };
        const writeString = (str) => {
            const bytes = new TextEncoder().encode(str);
            buffer.set(bytes, offset);
            offset += bytes.length;
        };

        const fileOffsets = [];

        // Local File Headers + Data
        for (const f of this.files) {
            fileOffsets.push(offset);
            writeUint32(0x04034b50); // Signature
            writeUint16(10); // Version
            writeUint16(0); // Flags
            writeUint16(0); // Compression (Stored)
            writeUint32(this._dateToDos(f.time));
            writeUint32(this._crc32(f.data));
            writeUint32(f.data.length); // Compressed size
            writeUint32(f.data.length); // Uncompressed size
            writeUint16(f.path.length);
            writeUint16(0); // Extra field len
            writeString(f.path);
            buffer.set(f.data, offset);
            offset += f.data.length;
        }

        const centralDirOffset = offset;

        // Central Directory
        for (let i = 0; i < this.files.length; i++) {
            const f = this.files[i];
            writeUint32(0x02014b50); // Signature
            writeUint16(20); // Version made by
            writeUint16(10); // Version needed
            writeUint16(0); // Flags
            writeUint16(0); // Compression
            writeUint32(this._dateToDos(f.time));
            writeUint32(this._crc32(f.data));
            writeUint32(f.data.length);
            writeUint32(f.data.length);
            writeUint16(f.path.length);
            writeUint16(0); // Extra
            writeUint16(0); // Comment
            writeUint16(0); // Disk
            writeUint16(0); // Internal attr
            writeUint32(0); // External attr
            writeUint32(fileOffsets[i]); // Local header offset
            writeString(f.path);
        }

        const endOfCentralDirOffset = offset;

        // End of Central Directory
        writeUint32(0x06054b50);
        writeUint16(0); // Disk num
        writeUint16(0); // Start disk
        writeUint16(this.files.length); // Records on disk
        writeUint16(this.files.length); // Total records
        writeUint32(endOfCentralDirOffset - centralDirOffset); // Size of central dir
        writeUint32(centralDirOffset); // Offset
        writeUint16(0); // Comment len

        return buffer;
    }

    _crc32(data) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < data.length; i++) {
            let byte = data[i];
            crc ^= byte;
            for (let j = 0; j < 8; j++) {
                crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
            }
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }
}

async function unpackSourceMap(url, hostname) {
    console.log('[BountySleuth] Starting unpack for:', url);

    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to fetch source map: HTTP ${resp.status}`);

    const text = await resp.text();
    console.log('[BountySleuth] Fetched source map, size:', text.length);

    let map;
    try {
        map = JSON.parse(text);
    } catch (e) {
        throw new Error('Source map is not valid JSON');
    }

    if (!map.sources || map.sources.length === 0) {
        throw new Error('Source map has no sources array');
    }

    if (!map.sourcesContent || map.sourcesContent.length === 0) {
        throw new Error('Source map does not contain embedded sourcesContent — cannot unpack');
    }

    const zip = new SimpleZipWriter();

    // Add the .map file itself inside src_unpacked
    const mapFileName = url.split('/').pop().split('?')[0] || 'source.map';
    zip.addFile('src_unpacked/' + mapFileName, text);

    // Reconstruct all source files
    let addedCount = 0;
    for (let i = 0; i < map.sources.length; i++) {
        const content = map.sourcesContent[i];
        if (!content) continue;

        let sourcePath = map.sources[i];
        // Normalize paths from various bundlers
        sourcePath = sourcePath
            .replace(/^webpack:\/\/\//i, '')
            .replace(/^webpack:\/\/[^/]*\//i, '')
            .replace(/^ng:\/\//i, '')
            .replace(/^\.\//g, '')
            .replace(/^\.\.\//g, 'parent/')
            .replace(/^[a-z]:\//i, '')
            .split('?')[0];

        // Skip empty paths
        if (!sourcePath || sourcePath === '') continue;

        zip.addFile('src_unpacked/' + sourcePath, content);
        addedCount++;
    }

    console.log('[BountySleuth] Added', addedCount, 'source files to ZIP');

    // Extract packages for the NPM analyzer
    const packageMap = {};

    // Filter out build tool artifacts and invalid package names
    const invalidPackagePatterns = [
        /^\./, // Packages starting with . (like .pnpm, .federation, .cache)
        /^_/, // Packages starting with _ (internal)
        /^node_modules$/, // The folder itself
        /^\d/, // Packages starting with numbers (invalid npm names)
    ];
    const buildToolArtifacts = new Set([
        '.pnpm', '.federation', '.cache', '.vite', '.turbo', '.next', '.nuxt',
        '.parcel-cache', '.webpack', '.rollup', '.esbuild', '.swc',
        'node_modules', '__virtual__', '__federation__', '__mf__'
    ]);

    map.sources.forEach(s => {
        const normalized = s
            .replace(/^webpack:\/\/\//i, '')
            .replace(/^webpack:\/\/[^/]*\//i, '')
            .replace(/^\.\//g, '');
        const nmMatch = normalized.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/);
        if (nmMatch) {
            const pkgName = nmMatch[1];

            // Skip invalid/artifact packages
            if (buildToolArtifacts.has(pkgName)) return;
            if (invalidPackagePatterns.some(pattern => pattern.test(pkgName))) return;
            // Skip if package name contains invalid characters for npm
            if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(pkgName)) return;

            if (!packageMap[pkgName]) {
                packageMap[pkgName] = { name: pkgName, fileCount: 0, isScoped: pkgName.startsWith('@') };
            }
            packageMap[pkgName].fileCount++;
        }
    });
    const extractedPackages = Object.values(packageMap).sort((a, b) => b.fileCount - a.fileCount);

    const zipData = zip.toUint8Array();
    const blob = new Blob([zipData], { type: 'application/zip' });
    const blobUrl = URL.createObjectURL(blob);
    const baseName = hostname || mapFileName.replace('.js.map', '').replace('.css.map', '').replace('.map', '');

    return new Promise((resolve, reject) => {
        chrome.downloads.download({
            url: blobUrl,
            filename: `BountySleuth_Unpacked/${baseName}_source_code.zip`,
            saveAs: false
        }, (downloadId) => {
            // Clean up the blob URL after a delay
            setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);

            if (chrome.runtime.lastError) {
                console.error('[BountySleuth] Download error:', chrome.runtime.lastError);
                reject(new Error(chrome.runtime.lastError.message));
            } else {
                console.log('[BountySleuth] Download started, ID:', downloadId);
                resolve({ downloadId, fileCount: addedCount, packages: extractedPackages });
            }
        });
    });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'downloadSourceMap' && request.url) {
        try {
            const filename = request.url.split('/').pop().split('?')[0] || 'sourcemap.map';
            chrome.downloads.download({
                url: request.url,
                filename: `BountySleuth_SourceMaps/${filename}`,
                saveAs: false
            }, (downloadId) => {
                if (chrome.runtime.lastError) {
                    console.error('BountySleuth download error:', chrome.runtime.lastError);
                }
            });
        } catch (e) {
            console.error('BountySleuth download error:', e);
        }
        sendResponse({ status: 'download_started' });
    } else if (request.action === 'unpackSourceMap' && request.url) {
        unpackSourceMap(request.url, request.hostname)
            .then(result => sendResponse({
                status: 'unpack_complete',
                downloadId: result.downloadId,
                fileCount: result.fileCount,
                packages: result.packages
            }))
            .catch(err => sendResponse({ status: 'error', message: err.message }));
        return true; // Keep channel open for async response
    } else if (request.action === 'checkNpmPackages' && request.packages) {
        // Check packages against npm registry for Dependency Confusion / Private Package Takeover
        (async () => {
            const results = [];
            const packages = request.packages.slice(0, 100); // Limit to 100 packages

            // Common internal package name patterns
            const internalPatterns = /^(internal|private|corp|company|enterprise|infra|platform|core|shared|common|utils|helpers|lib|sdk|api|service|app|web|mobile|admin|portal|dashboard|config|build|deploy|ci|cd|test|mock|stub|fixture|seed|migration|script|tool|cli|pkg|module|component|widget|ui|ux|design|style|theme|asset|resource|vendor|third-party|legacy|deprecated|old|new|temp|tmp|dev|prod|stage|staging|qa|uat|local|docker|k8s|kubernetes|aws|azure|gcp|cloud)/i;

            for (const pkg of packages) {
                try {
                    const encodedName = pkg.name.replace('/', '%2F');
                    const resp = await fetch(`https://registry.npmjs.org/${encodedName}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' }
                    });

                    if (resp.ok) {
                        // Package exists on public npm
                        const data = await resp.json();
                        const latestVersion = data['dist-tags'] ? data['dist-tags'].latest : 'unknown';
                        results.push({
                            name: pkg.name,
                            fileCount: pkg.fileCount,
                            isScoped: pkg.isScoped,
                            isPublic: true,
                            isTakeoverTarget: false,
                            npmUrl: `https://www.npmjs.com/package/${pkg.name}`,
                            description: (data.description || '').substring(0, 100),
                            latestVersion,
                            severity: 'OK',
                            verdict: 'Public package'
                        });
                    } else if (resp.status === 404) {
                        // Package NOT on public npm — analyze takeover risk
                        const isScoped = pkg.isScoped || pkg.name.startsWith('@');
                        const pkgNameOnly = isScoped ? pkg.name.split('/')[1] : pkg.name;
                        const looksInternal = internalPatterns.test(pkgNameOnly);

                        // CRITICAL: Unscoped packages can be registered by ANYONE
                        // HIGH: Scoped packages need scope ownership but still notable
                        let severity = 'HIGH';
                        let verdict = '';
                        let takeoverUrl = null;

                        if (!isScoped) {
                            // CRITICAL - Anyone can register this on npm right now!
                            severity = 'CRITICAL';
                            verdict = '🚨 TAKEOVER POSSIBLE — Unscoped private package, anyone can claim on npm!';
                            takeoverUrl = `https://www.npmjs.com/package/${pkg.name}`;
                        } else {
                            // Scoped package - need to own the scope
                            const scope = pkg.name.split('/')[0];
                            verdict = `⚠️ Private scoped package (${scope}) — Check if scope is claimed`;
                            takeoverUrl = `https://www.npmjs.com/org/${scope.replace('@', '')}`;
                        }

                        results.push({
                            name: pkg.name,
                            fileCount: pkg.fileCount,
                            isScoped: isScoped,
                            isPublic: false,
                            isTakeoverTarget: !isScoped, // Unscoped = immediate target
                            looksInternal: looksInternal,
                            npmUrl: null,
                            takeoverUrl: takeoverUrl,
                            description: null,
                            latestVersion: null,
                            severity: severity,
                            verdict: verdict
                        });
                    } else {
                        results.push({
                            name: pkg.name,
                            fileCount: pkg.fileCount,
                            isScoped: pkg.isScoped,
                            isPublic: null,
                            isTakeoverTarget: false,
                            severity: 'UNKNOWN',
                            verdict: `Check failed: HTTP ${resp.status}`,
                            error: `HTTP ${resp.status}`
                        });
                    }
                } catch (e) {
                    results.push({
                        name: pkg.name,
                        fileCount: pkg.fileCount,
                        isScoped: pkg.isScoped,
                        isPublic: null,
                        isTakeoverTarget: false,
                        severity: 'UNKNOWN',
                        verdict: `Check failed: ${e.message}`,
                        error: e.message
                    });
                }
            }

            // Sort: CRITICAL first, then HIGH, then rest
            results.sort((a, b) => {
                const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'UNKNOWN': 3, 'OK': 4 };
                return (order[a.severity] || 5) - (order[b.severity] || 5);
            });

            sendResponse({ status: 'done', results });
        })();
        return true; // Keep channel open for async
    }
    return true;
});
