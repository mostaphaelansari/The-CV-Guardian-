/* ═══════════════════════════════════════════════
   CV Shield — Client Application Logic
   ═══════════════════════════════════════════════ */

(() => {
    'use strict';

    // ── DOM refs ──
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const uploadSection = document.getElementById('uploadSection');
    const progressSection = document.getElementById('progressSection');
    const resultsSection = document.getElementById('resultsSection');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const progressSteps = document.getElementById('progressSteps');
    const scoreValue = document.getElementById('scoreValue');
    const scoreLabel = document.getElementById('scoreLabel');
    const riskBadge = document.getElementById('riskBadge');
    const gaugeFill = document.getElementById('gaugeFill');
    const scoreCard = document.getElementById('scoreCard');
    const fileInfo = document.getElementById('fileInfo');
    const summaryText = document.getElementById('summaryText');
    const recommendations = document.getElementById('recommendations');
    const findingsBody = document.getElementById('findingsBody');
    const findingsCount = document.getElementById('findingsCount');
    const newScanBtn = document.getElementById('newScanBtn');
    const historyList = document.getElementById('historyList');
    const totalScanned = document.getElementById('totalScanned');
    const totalThreats = document.getElementById('totalThreats');
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');

    // ── State ──
    let history = [];
    let scanCount = 0;
    let threatCount = 0;

    // ── Constants ──
    const GAUGE_CIRCUMFERENCE = 326.73;
    const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

    /* ─────────────────────────────────────────────
     * Event listeners
     * ────────────────────────────────────────────── */

    // Upload zone click
    uploadZone.addEventListener('click', () => fileInput.click());

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
    });

    // Drag & drop
    uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
    uploadZone.addEventListener('drop', e => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
    });

    // New scan
    newScanBtn.addEventListener('click', resetToUpload);

    // Mobile menu
    menuToggle.addEventListener('click', () => sidebar.classList.toggle('open'));

    /* ─────────────────────────────────────────────
     * File handling
     * ────────────────────────────────────────────── */
    function handleFile(file) {
        // Validate type
        const validTypes = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ];
        const validExts = ['.pdf', '.docx', '.txt'];

        const isTypeValid = validTypes.includes(file.type);
        const isExtValid = validExts.some(ext => file.name.toLowerCase().endsWith(ext));

        if (!isTypeValid && !isExtValid) {
            showToast('❌ Only PDF, DOCX, and TXT files are accepted');
            return;
        }
        // Validate size (15 MB)
        if (file.size > 15 * 1024 * 1024) {
            showToast('❌ File exceeds 15 MB limit');
            return;
        }

        uploadAndAnalyze(file);
    }

    /* ─────────────────────────────────────────────
     * Upload & analysis pipeline
     * ────────────────────────────────────────────── */
    async function uploadAndAnalyze(file) {
        showProgress();
        simulateSteps();

        const formData = new FormData();
        formData.append('pdf', file);

        try {
            const res = await fetch('/api/analyze', { method: 'POST', body: formData });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || 'Server error');
            }

            const report = await res.json();
            completeProgress(() => showResults(report));

        } catch (err) {
            showToast('❌ ' + err.message);
            resetToUpload();
        }
    }

    /* ─────────────────────────────────────────────
     * Progress simulation
     * ────────────────────────────────────────────── */
    function showProgress() {
        uploadSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        progressSection.classList.remove('hidden');
        progressBar.style.width = '0%';

        // reset steps
        const steps = progressSteps.querySelectorAll('.step');
        steps.forEach(s => { s.classList.remove('active', 'done'); });
        steps[0].classList.add('active');
    }

    function simulateSteps() {
        const steps = progressSteps.querySelectorAll('.step');
        const labels = [
            'Uploading PDF…',
            'Parsing document structure…',
            'Checking for JavaScript…',
            'Scanning URLs…',
            'Inspecting embedded objects…',
            'Analysing metadata…',
            'Generating report…'
        ];

        let i = 0;
        const interval = setInterval(() => {
            if (i >= steps.length - 1) { clearInterval(interval); return; }
            steps[i].classList.remove('active');
            steps[i].classList.add('done');
            i++;
            steps[i].classList.add('active');
            progressText.textContent = labels[i] || 'Analysing…';
            progressBar.style.width = `${((i + 1) / steps.length) * 100}%`;
        }, 400);
    }

    function completeProgress(cb) {
        const steps = progressSteps.querySelectorAll('.step');
        steps.forEach(s => { s.classList.remove('active'); s.classList.add('done'); });
        progressBar.style.width = '100%';
        progressText.textContent = 'Analysis complete ✓';
        setTimeout(cb, 600);
    }

    /* ─────────────────────────────────────────────
     * Render results
     * ────────────────────────────────────────────── */
    function showResults(report) {
        progressSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        // ── Score gauge ──
        animateScore(report.score);
        scoreLabel.textContent = 'Threat Score';
        riskBadge.textContent = report.riskLevel.toUpperCase();
        riskBadge.className = `risk-badge badge-${report.riskLevel}`;

        // Colour the gauge
        const clr = riskColor(report.riskLevel);
        gaugeFill.style.stroke = clr;
        scoreCard.style.borderColor = clr + '33';

        // ── File info ──
        fileInfo.innerHTML = infoRow('File', report.fileName)
            + infoRow('Size', formatBytes(report.fileSize))
            + infoRow('Pages', report.pageCount)
            + infoRow('Creator', report.metadata?.creator || '—')
            + infoRow('Producer', report.metadata?.producer || '—')
            + infoRow('Scanned', new Date(report.analyzedAt).toLocaleString());

        // ── Summary ──
        summaryText.textContent = report.summary;

        // ── Recommendations ──
        recommendations.innerHTML = report.recommendations
            .map(r => `<div class="rec-item">${r}</div>`)
            .join('');

        // ── Findings ──
        if (report.findings.length === 0) {
            findingsBody.innerHTML = '<p class="no-findings">✅ No threats detected — this resume appears clean</p>';
        } else {
            const sorted = [...report.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
            findingsBody.innerHTML = sorted.map((f, i) => `
        <div class="finding-row" style="animation-delay: ${i * 0.06}s">
          <span class="finding-check">${f.check}</span>
          <span class="finding-severity severity-${f.severity}">${f.severity}</span>
          <span class="finding-message">${escapeHtml(f.message)}</span>
        </div>
      `).join('');
        }
        findingsCount.textContent = `${report.findings.length} finding${report.findings.length !== 1 ? 's' : ''}`;

        // ── Sanitization status card ──
        const sanitizationBadge = document.getElementById('sanitizationBadge');
        const sanitizationDetails = document.getElementById('sanitizationDetails');
        const isolationTemplateWrapper = document.getElementById('isolationTemplateWrapper');
        const isolationTemplate = document.getElementById('isolationTemplate');
        const copyTemplateBtn = document.getElementById('copyTemplateBtn');

        if (report.safeForLLM) {
            sanitizationBadge.className = 'sanitization-badge badge-safe';
            sanitizationBadge.innerHTML = '✅ Safe for Processing';
            sanitizationDetails.innerHTML = '<p class="sanitization-clean">No injection patterns detected — content is clean for downstream use.</p>';
            isolationTemplateWrapper.classList.add('hidden');
        } else {
            const logCount = (report.sanitizationLog || []).length;
            const totalRedacted = (report.sanitizationLog || []).reduce((sum, e) => sum + e.count, 0);
            sanitizationBadge.className = 'sanitization-badge badge-warning';
            sanitizationBadge.innerHTML = `⚠️ Sanitized — ${totalRedacted} injection${totalRedacted !== 1 ? 's' : ''} neutralized (${logCount} pattern${logCount !== 1 ? 's' : ''})`;
            sanitizationDetails.innerHTML = (report.sanitizationLog || []).map(entry =>
                `<div class="sanitization-entry">
                    <span class="sanitization-label">${escapeHtml(entry.label)}</span>
                    <span class="sanitization-count">${entry.count}×</span>
                </div>`
            ).join('');

            if (report.contentIsolationTemplate) {
                isolationTemplateWrapper.classList.remove('hidden');
                isolationTemplate.textContent = report.contentIsolationTemplate;
                copyTemplateBtn.onclick = () => {
                    navigator.clipboard.writeText(report.contentIsolationTemplate)
                        .then(() => showToast('📋 Template copied to clipboard'))
                        .catch(() => showToast('❌ Copy failed'));
                };
            } else {
                isolationTemplateWrapper.classList.add('hidden');
            }
        }

        // ── Update sidebar ──
        scanCount++;
        if (report.riskLevel === 'high' || report.riskLevel === 'critical') threatCount++;
        totalScanned.textContent = scanCount;
        totalThreats.textContent = threatCount;
        addHistoryItem(report);
    }

    function animateScore(target) {
        let current = 0;
        const step = Math.max(1, Math.ceil(target / 40));
        const timer = setInterval(() => {
            current = Math.min(current + step, target);
            scoreValue.textContent = current;

            // Update gauge offset
            const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * current / 100);
            gaugeFill.style.strokeDashoffset = offset;

            if (current >= target) clearInterval(timer);
        }, 30);
    }

    function riskColor(level) {
        const map = { safe: '#34d399', low: '#6ee7b7', medium: '#fbbf24', high: '#f97316', critical: '#ef4444' };
        return map[level] || '#94a3b8';
    }

    /* ─────────────────────────────────────────────
     * History sidebar
     * ────────────────────────────────────────────── */
    function addHistoryItem(report) {
        history.unshift(report);
        renderHistory();
    }

    function renderHistory() {
        if (history.length === 0) {
            historyList.innerHTML = '<div class="history-empty"><span class="history-empty-icon">📋</span><p>No analyses yet</p></div>';
            return;
        }

        historyList.innerHTML = history.map(r => `
      <div class="history-item" data-id="${r.id}">
        <div class="history-name">${escapeHtml(r.fileName)}</div>
        <div class="history-meta">
          <span class="history-time">${timeAgo(r.analyzedAt)}</span>
          <span class="history-badge badge-${r.riskLevel}">${r.riskLevel}</span>
        </div>
      </div>
    `).join('');

        // Click to re-show a past report
        historyList.querySelectorAll('.history-item').forEach(el => {
            el.addEventListener('click', () => {
                const r = history.find(h => h.id === el.dataset.id);
                if (r) showResults(r);
                sidebar.classList.remove('open');
            });
        });
    }

    /* ─────────────────────────────────────────────
     * Reset
     * ────────────────────────────────────────────── */
    function resetToUpload() {
        resultsSection.classList.add('hidden');
        progressSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        fileInput.value = '';
        // Reset gauge
        gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
        scoreValue.textContent = '0';
    }

    /* ─────────────────────────────────────────────
     * Helpers
     * ────────────────────────────────────────────── */
    function infoRow(label, value) {
        return `<div class="info-row"><span class="info-label">${label}</span><span class="info-value">${escapeHtml(String(value ?? '—'))}</span></div>`;
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function timeAgo(isoDate) {
        const diff = (Date.now() - new Date(isoDate).getTime()) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    function showToast(message) {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

})();
