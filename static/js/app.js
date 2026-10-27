function showToast(msg) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2600);
}

document.addEventListener('DOMContentLoaded', () => {
    let currentTarget = 'vatssi.in';

    // DOM Elements
    const targetInput = document.getElementById('global-target-input');
    const btnScanAll = document.getElementById('btn-scan-all');
    const btnExportDossier = document.getElementById('btn-export-dossier');
    const btnThemeToggle = document.getElementById('btn-theme-toggle');
    const navItems = document.querySelectorAll('.nav-item');
    const viewPanels = document.querySelectorAll('.view-panel');

    // KPI Elements
    const kpiSubs = document.getElementById('kpi-subs');
    const kpiPorts = document.getElementById('kpi-ports');
    const kpiSsl = document.getElementById('kpi-ssl');
    const kpiGrade = document.getElementById('kpi-grade');

    // Terminal clear & copy
    const btnClearTerm = document.getElementById('btn-clear-term');
    const btnCopyTerm = document.getElementById('btn-copy-term');

    if (btnClearTerm) btnClearTerm.addEventListener('click', () => window.term.clear());
    if (btnCopyTerm) btnCopyTerm.addEventListener('click', () => window.term.copy());

    window.term.log('Vatsal\'s SecOps Reconnaissance Console v2.5 initialized.');
    window.term.log('Ready for active audit. Enter target host and execute scan.');

    // Navigation Switcher
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const viewId = item.dataset.view;
            if (!viewId) return;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            viewPanels.forEach(p => p.classList.remove('active'));
            const targetPanel = document.getElementById(`panel-${viewId}`);
            if (targetPanel) targetPanel.classList.add('active');

            window.term.log(`Switched view context to module: [${viewId.toUpperCase()}]`);
        });
    });

    // Theme Toggle
    if (btnThemeToggle) {
        btnThemeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', nextTheme);
            showToast(`Switched to ${nextTheme === 'light' ? 'Light Mode' : 'Dark SecOps Mode'}`);
        });
    }

    // Helper: Normalize target
    function getCleanTarget() {
        if (!targetInput) return 'vatssi.in';
        return targetInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0] || 'vatssi.in';
    }

    // =========================================================================
    // MODULE 1: DNS & RECORD RESOLUTION
    // =========================================================================
    async function runDNS() {
        const domain = getCleanTarget();
        window.term.log(`[DNS] Initiating deep record matrix query for: ${domain}`);
        const tbody = document.getElementById('table-dns-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:16px;">Resolving DNS records...</td></tr>';

        try {
            const res = await fetch(`/api/recon/dns?domain=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            let rowsHtml = '';
            for (const [rtype, list] of Object.entries(data.records || {})) {
                list.forEach(rec => {
                    let badgeClass = 'badge-info';
                    let finding = 'NORMAL';
                    if (rtype === 'A') finding = 'RESOLVED';
                    if (rtype === 'MX') finding = 'MAIL SERVER';
                    if (rtype === 'CNAME') {
                        finding = 'ALIAS';
                        if (data.dangling_cnames && data.dangling_cnames.length > 0) {
                            badgeClass = 'badge-danger';
                            finding = 'CHECK DANGLING';
                        }
                    }

                    rowsHtml += `<tr>
                        <td><span class="badge ${badgeClass}">${rtype}</span></td>
                        <td style="font-family:var(--font-mono);">${domain}</td>
                        <td style="font-family:var(--font-mono); word-break:break-all;">${rec}</td>
                        <td><span class="badge ${badgeClass}">${finding}</span></td>
                    </tr>`;
                });
            }

            if (!rowsHtml) {
                rowsHtml = '<tr><td colspan="4" style="text-align:center;">No records discovered.</td></tr>';
            }
            if (tbody) tbody.innerHTML = rowsHtml;

        } catch (e) {
            window.term.log(`[-] DNS API error: ${e.message}; trying DoH fallback...`);
            await runDnsDoHFallback(domain);
        }
    }

    // Client-side DoH fallback for static deploy
    async function runDnsDoHFallback(domain) {
        const tbody = document.getElementById('table-dns-body');
        try {
            const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            const data = await resp.json();
            const answers = data.Answer || [];
            let rowsHtml = '';
            answers.forEach(a => {
                rowsHtml += `<tr>
                    <td><span class="badge badge-info">A</span></td>
                    <td style="font-family:var(--font-mono);">${domain}</td>
                    <td style="font-family:var(--font-mono);">${a.data}</td>
                    <td><span class="badge badge-success">DoH RESOLVED</span></td>
                </tr>`;
            });
            if (tbody) tbody.innerHTML = rowsHtml || '<tr><td colspan="4" style="text-align:center;">No A records found.</td></tr>';
            window.term.log(`[+] Cloudflare DoH fallback resolved ${answers.length} address records.`);
        } catch (err) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--accent-red);">Resolution timed out.</td></tr>';
        }
    }

    // =========================================================================
    // MODULE 2: SUBDOMAIN ENUMERATION
    // =========================================================================
    async function runSubdomains() {
        const domain = getCleanTarget();
        window.term.log(`[CT-LOGS] Harvesting Certificate Transparency logs for: ${domain}`);
        const tbody = document.getElementById('table-subs-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:16px;">Querying certificate transparency indexes...</td></tr>';

        try {
            const res = await fetch(`/api/recon/subdomains?domain=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            let rows = '';
            (data.subdomains || []).forEach(sub => {
                const badge = sub.is_live ? '<span class="badge badge-success">LIVE ACTIVE</span>' : '<span class="badge badge-warning">HISTORICAL</span>';
                rows += `<tr>
                    <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${sub.subdomain}</td>
                    <td style="font-family:var(--font-mono);">${sub.ip}</td>
                    <td>${sub.status}</td>
                    <td>${badge}</td>
                </tr>`;
            });

            if (tbody) tbody.innerHTML = rows || '<tr><td colspan="4" style="text-align:center;">No subdomains logged.</td></tr>';
            if (kpiSubs) kpiSubs.textContent = `${data.live_count || 0} Live`;

        } catch (e) {
            window.term.log(`[-] Subdomain API unavailable: ${e.message}`);
        }
    }

    // =========================================================================
    // MODULE 3: WHOIS & RDAP INTEL
    // =========================================================================
    async function runWhois() {
        const domain = getCleanTarget();
        window.term.log(`[WHOIS] Querying authoritative registry & RDAP for: ${domain}`);

        try {
            const res = await fetch(`/api/recon/whois?domain=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            document.getElementById('whois-reg').textContent = data.registrar || 'Unknown';
            document.getElementById('whois-created').textContent = data.creation_date || 'N/A';
            document.getElementById('whois-expiry').textContent = data.expiration_date || 'N/A';
            document.getElementById('whois-source').textContent = data.whois_source || 'RDAP';
            document.getElementById('whois-ns').textContent = (data.name_servers || []).join(', ') || 'N/A';
            document.getElementById('whois-raw').textContent = data.raw_output || 'No raw output returned.';

        } catch (e) {
            window.term.log(`[-] WHOIS API call failed: ${e.message}`);
        }
    }

    // =========================================================================
    // MODULE 4: HEADERS & DEFENSIVE POSTURE
    // =========================================================================
    async function runHeaders() {
        const domain = getCleanTarget();
        window.term.log(`[HEADERS] Probing TLS HTTP security headers & CSP for: ${domain}`);

        try {
            const res = await fetch(`/api/recon/headers?domain=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            if (kpiGrade) kpiGrade.textContent = `Grade ${data.posture_grade} (${data.posture_score}/100)`;
            document.getElementById('headers-grade').textContent = data.posture_grade;
            document.getElementById('headers-score').textContent = `${data.posture_score} / 100`;
            document.getElementById('headers-waf').textContent = data.detected_waf;
            document.getElementById('headers-server').textContent = data.server_software;

            const tbody = document.getElementById('table-headers-body');
            let rows = '';
            (data.detailed_findings || []).forEach(f => {
                const badge = f.status === 'PASS' 
                    ? '<span class="badge badge-success">PASS</span>' 
                    : (f.status === 'WARN' ? '<span class="badge badge-warning">WARN</span>' : '<span class="badge badge-danger">FAIL</span>');

                rows += `<tr>
                    <td style="font-weight:600; color:var(--text-primary);">${f.header}</td>
                    <td>${badge}</td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem;">${f.value}</td>
                    <td style="color:var(--text-muted); font-size:0.75rem;">${f.importance}</td>
                </tr>`;
            });
            if (tbody) tbody.innerHTML = rows;

        } catch (e) {
            window.term.log(`[-] Headers probe failed: ${e.message}`);
        }
    }

    // =========================================================================
    // MODULE 5: SSL / TLS INSPECTOR
    // =========================================================================
    async function runSSL() {
        const domain = getCleanTarget();
        window.term.log(`[SSL/TLS] Inspecting cryptographic certificate parameters for: ${domain}:443`);

        try {
            const res = await fetch(`/api/recon/ssl?domain=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            if (kpiSsl) kpiSsl.textContent = data.has_ssl ? (data.tls_version || 'Valid TLS') : 'No SSL';
            document.getElementById('ssl-subject').textContent = data.subject_cn || 'N/A';
            document.getElementById('ssl-issuer').textContent = `${data.issuer_org} (${data.issuer_cn})`;
            document.getElementById('ssl-expiry').textContent = `${data.valid_until} (${data.days_remaining} days left)`;
            document.getElementById('ssl-protocol').textContent = `${data.tls_version} / ${data.cipher_suite}`;
            document.getElementById('ssl-sans').textContent = (data.sans || []).slice(0, 10).join(', ') || 'N/A';

        } catch (e) {
            window.term.log(`[-] SSL inspection error: ${e.message}`);
        }
    }

    // =========================================================================
    // MODULE 6: PORT SCANNER
    // =========================================================================
    async function runPorts() {
        const domain = getCleanTarget();
        window.term.log(`[PORTS] Dispatched non-blocking async socket scanner against: ${domain}`);
        const tbody = document.getElementById('table-ports-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:16px;">Scanning top ports...</td></tr>';

        try {
            const res = await fetch(`/api/recon/ports?target=${encodeURIComponent(domain)}&profile=quick`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            const openList = data.open_ports || [];
            if (kpiPorts) kpiPorts.textContent = `${openList.length} Open`;

            let rows = '';
            openList.forEach(p => {
                const riskBadge = p.risk === 'HIGH' ? '<span class="badge badge-danger">HIGH RISK</span>' : '<span class="badge badge-success">STANDARD</span>';
                rows += `<tr>
                    <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan);">${p.port}</td>
                    <td><span class="badge badge-success">OPEN</span></td>
                    <td>${p.service}</td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem;">${p.banner}</td>
                    <td>${riskBadge}</td>
                </tr>`;
            });

            if (!rows) {
                rows = '<tr><td colspan="5" style="text-align:center; color:var(--accent-green);">No exposed TCP ports discovered on standard profile.</td></tr>';
            }
            if (tbody) tbody.innerHTML = rows;

        } catch (e) {
            window.term.log(`[-] Port scan error: ${e.message}`);
        }
    }

    // =========================================================================
    // MODULE 7: IP GEOLOCATION & ASN
    // =========================================================================
    async function runGeo() {
        const domain = getCleanTarget();
        window.term.log(`[GEO-IP] Querying BGP Autonomous System and physical geolocation for: ${domain}`);

        try {
            const res = await fetch(`/api/recon/geo?target=${encodeURIComponent(domain)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            (data.logs || []).forEach(l => window.term.log(l));

            document.getElementById('geo-ip').textContent = data.ip;
            document.getElementById('geo-asn').textContent = data.asn;
            document.getElementById('geo-location').textContent = `${data.city}, ${data.region}, ${data.country} (${data.country_code})`;
            document.getElementById('geo-isp').textContent = data.isp;
            document.getElementById('geo-coords').textContent = `${data.latitude}, ${data.longitude}`;

        } catch (e) {
            window.term.log(`[-] GeoIP error: ${e.message}`);
        }
    }

    // =========================================================================
    // GLOBAL "SCAN TARGET" ORCHESTRATOR
    // =========================================================================
    async function executeFullAudit() {
        const domain = getCleanTarget();
        showToast(`Running Full Reconnaissance on ${domain}...`);
        window.term.log(`=================================================================`);
        window.term.log(`[ORCHESTRATOR] Commencing comprehensive audit on: ${domain}`);
        window.term.log(`=================================================================`);

        // Execute in parallel
        await Promise.all([
            runDNS(),
            runSubdomains(),
            runWhois(),
            runHeaders(),
            runSSL(),
            runPorts(),
            runGeo()
        ]);

        showToast(`Audit Completed for ${domain}!`);
        window.term.log(`[ORCHESTRATOR] Full reconnaissance complete. Dossier ready for export.`);
    }

    if (btnScanAll) btnScanAll.addEventListener('click', executeFullAudit);
    if (targetInput) {
        targetInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') executeFullAudit();
        });
    }

    // Export Dossier Trigger
    if (btnExportDossier) {
        btnExportDossier.addEventListener('click', () => {
            const domain = getCleanTarget();
            showToast('Downloading Markdown Audit Dossier...');
            window.open(`/api/recon/export-dossier?domain=${encodeURIComponent(domain)}`, '_blank');
        });
    }

    // =========================================================================
    // INTERACTIVE TOOLS: PASSWORD ENTROPY, HASHES, CIDR
    // =========================================================================
    const pwdInput = document.getElementById('pwd-test-input');
    if (pwdInput) {
        pwdInput.addEventListener('input', async () => {
            const val = pwdInput.value;
            if (!val) return;
            try {
                const res = await fetch('/api/recon/password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: val })
                });
                const d = await res.json();
                document.getElementById('pwd-shannon').textContent = `${d.shannon_entropy} bits/sym`;
                document.getElementById('pwd-entropy').textContent = `${d.entropy_bits} bits`;
                document.getElementById('pwd-crack').textContent = d.crack_time_estimate;
                document.getElementById('pwd-rating').textContent = d.rating;
            } catch (e) {}
        });
    }

    const hashInput = document.getElementById('hash-test-input');
    if (hashInput) {
        hashInput.addEventListener('input', async () => {
            const val = hashInput.value;
            if (!val) return;
            try {
                const res = await fetch('/api/recon/hashes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: val })
                });
                const d = await res.json();
                document.getElementById('hash-md5').textContent = d.md5;
                document.getElementById('hash-sha256').textContent = d.sha256;
                document.getElementById('hash-base64').textContent = d.base64_encoded;
            } catch (e) {}
        });
    }

    const cidrInput = document.getElementById('cidr-test-input');
    const btnCalcCidr = document.getElementById('btn-calc-cidr');
    if (btnCalcCidr && cidrInput) {
        btnCalcCidr.addEventListener('click', async () => {
            const val = cidrInput.value.trim();
            if (!val) return;
            try {
                const res = await fetch(`/api/recon/subnet?cidr=${encodeURIComponent(val)}`);
                const d = await res.json();
                if (d.error) {
                    showToast(d.error);
                    return;
                }
                document.getElementById('cidr-net').textContent = d.network_address;
                document.getElementById('cidr-bcast').textContent = d.broadcast_address;
                document.getElementById('cidr-netmask').textContent = d.netmask;
                document.getElementById('cidr-hosts').textContent = `${d.usable_hosts} hosts (${d.first_usable_ip} - ${d.last_usable_ip})`;
                window.term.log(`[CIDR] Calculated subnet ${d.cidr}: ${d.usable_hosts} usable IP addresses.`);
            } catch (e) {}
        });
    }

    // Auto-run initial audit on load
    executeFullAudit();
});
