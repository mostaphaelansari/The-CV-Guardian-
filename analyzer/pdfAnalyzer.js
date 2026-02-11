const pdfParse = require('pdf-parse');

/**
 * Main PDF Analyzer – performs 7 security checks on uploaded CV/resume PDFs.
 * Returns a structured threat report with score, risk level, findings, and recommendations.
 */
class PDFAnalyzer {

  constructor() {
    // ── Suspicious URL patterns ──
    this.suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js', '.wsf', '.msi', '.ps1'];
    this.urlShorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at'];

    // ── Dangerous PDF operators / dictionary keys ──
    this.dangerousKeys = [
      '/JS', '/JavaScript', '/Launch', '/OpenAction', '/AA',
      '/EmbeddedFile', '/RichMedia', '/XFA', '/AcroForm',
      '/SubmitForm', '/ImportData', '/URI', '/GoToR', '/GoToE'
    ];

    // ── Obfuscation-related stream filters ──
    this.suspiciousFilters = [
      '/ASCIIHexDecode', '/ASCII85Decode', '/Crypt',
      '/JBIG2Decode', '/DCTDecode', '/JPXDecode'
    ];

    // ── Suspicious text keywords (should NOT appear in a CV) ──
    this.suspiciousKeywords = [
      'click here to enable',
      'enable macros',
      'enable content',
      'enable editing',
      'password is',
      'run this file',
      'open attachment',
      'powershell',
      'cmd.exe',
      'wget ',
      'curl ',
      'base64',
      'invoke-expression',
      'system32',
      'reg add',
      'bitcoin',
      'cryptocurrency wallet',
      'wire transfer',
      'pay the ransom'
    ];
  }

  /**
   * Analyse a PDF buffer and return a threat report.
   * @param {Buffer} fileBuffer – raw PDF bytes
   * @param {string} fileName  – original file name
   * @returns {Promise<object>} threat report
   */
  async analyze(fileBuffer, fileName) {
    const report = {
      fileName,
      fileSize: fileBuffer.length,
      analyzedAt: new Date().toISOString(),
      findings: [],
      score: 0,          // 0 – 100  (higher = more dangerous)
      riskLevel: 'safe',  // safe | low | medium | high | critical
      summary: '',
      recommendations: [],
      metadata: {},
      pageCount: 0
    };

    try {
      // ── Parse PDF ──
      const pdfData = await pdfParse(fileBuffer);
      report.pageCount = pdfData.numpages || 0;
      report.metadata = this._extractMetadata(pdfData);

      const rawText = pdfData.text || '';
      const rawBuffer = fileBuffer.toString('latin1');   // raw bytes as string for pattern scanning

      // ── Run all 7 checks ──
      this._checkJavaScript(rawBuffer, report);
      this._checkSuspiciousURLs(rawText, rawBuffer, report);
      this._checkEmbeddedObjects(rawBuffer, report);
      this._checkMetadataAnomalies(report);
      this._checkObfuscation(rawBuffer, report);
      this._checkContentHeuristics(rawText, report);
      this._checkStructure(fileBuffer, pdfData, report);

    } catch (err) {
      report.findings.push({
        check: 'PDF Parsing',
        severity: 'high',
        message: `Failed to parse PDF: ${err.message}. Corrupted or malformed PDFs can themselves be an attack vector.`
      });
      report.score += 30;
    }

    // ── Finalise score & risk level ──
    report.score = Math.min(report.score, 100);
    report.riskLevel = this._riskLevel(report.score);
    report.summary = this._buildSummary(report);
    report.recommendations = this._buildRecommendations(report);

    return report;
  }

  /* ─────────────────────────────────────────────
   * CHECK 1 – JavaScript Detection
   * ────────────────────────────────────────────── */
  _checkJavaScript(raw, report) {
    const jsPatterns = [
      { pattern: /\/JavaScript/gi,  label: '/JavaScript action' },
      { pattern: /\/JS\s/gi,       label: '/JS action' },
      { pattern: /eval\s*\(/gi,    label: 'eval() call' },
      { pattern: /app\.\w+/gi,     label: 'Acrobat app object reference' },
      { pattern: /this\.submitForm/gi, label: 'submitForm call' },
      { pattern: /this\.exportDataObject/gi, label: 'exportDataObject call' },
      { pattern: /util\.printf/gi,  label: 'util.printf (potential heap spray)' },
      { pattern: /String\.fromCharCode/gi, label: 'String.fromCharCode (potential obfuscation)' }
    ];

    let found = false;
    for (const { pattern, label } of jsPatterns) {
      const matches = raw.match(pattern);
      if (matches && matches.length > 0) {
        found = true;
        report.findings.push({
          check: 'JavaScript Detection',
          severity: 'critical',
          message: `Found ${matches.length}× ${label}`,
          count: matches.length
        });
      }
    }

    if (found) report.score += 35;
  }

  /* ─────────────────────────────────────────────
   * CHECK 2 – Suspicious URLs
   * ────────────────────────────────────────────── */
  _checkSuspiciousURLs(text, raw, report) {
    // Extract all URLs from both text and raw stream
    const urlRegex = /https?:\/\/[^\s"'<>)\]]+/gi;
    const urls = [...new Set([...(text.match(urlRegex) || []), ...(raw.match(urlRegex) || [])])];

    if (urls.length === 0) return;

    let suspiciousCount = 0;
    for (const url of urls) {
      const lower = url.toLowerCase();

      // Check executable download links
      for (const ext of this.suspiciousExtensions) {
        if (lower.includes(ext)) {
          report.findings.push({
            check: 'Suspicious URLs',
            severity: 'high',
            message: `URL points to dangerous file type (${ext}): ${url.substring(0, 80)}…`
          });
          suspiciousCount++;
          break;
        }
      }

      // Check URL shorteners
      for (const shortener of this.urlShorteners) {
        if (lower.includes(shortener)) {
          report.findings.push({
            check: 'Suspicious URLs',
            severity: 'medium',
            message: `URL shortener detected (${shortener}): ${url.substring(0, 80)}…`
          });
          suspiciousCount++;
          break;
        }
      }

      // Check IP-based URLs (instead of domain names)
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
        report.findings.push({
          check: 'Suspicious URLs',
          severity: 'high',
          message: `IP-based URL detected (no domain): ${url.substring(0, 80)}…`
        });
        suspiciousCount++;
      }
    }

    // Check for data URIs
    const dataURIs = raw.match(/data:[a-z]+\/[a-z]+;base64,/gi);
    if (dataURIs && dataURIs.length > 0) {
      report.findings.push({
        check: 'Suspicious URLs',
        severity: 'high',
        message: `${dataURIs.length}× data URI with base64 payload detected`
      });
      suspiciousCount++;
    }

    if (suspiciousCount > 0) {
      report.score += Math.min(suspiciousCount * 10, 25);
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 3 – Embedded Objects & Auto-Actions
   * ────────────────────────────────────────────── */
  _checkEmbeddedObjects(raw, report) {
    const dangerousFound = [];

    for (const key of this.dangerousKeys) {
      const regex = new RegExp(key.replace('/', '\\/'), 'gi');
      const matches = raw.match(regex);
      if (matches && matches.length > 0) {
        dangerousFound.push({ key, count: matches.length });
      }
    }

    // Filter out common safe keys (/URI is common in normal PDFs with links)
    const trulyDangerous = dangerousFound.filter(d =>
      !['/URI'].includes(d.key) || d.count > 10
    );

    for (const { key, count } of trulyDangerous) {
      const severity = ['/Launch', '/JavaScript', '/JS', '/EmbeddedFile', '/OpenAction', '/AA'].includes(key)
        ? 'critical'
        : 'high';

      report.findings.push({
        check: 'Embedded Objects',
        severity,
        message: `Found ${count}× dangerous PDF key: ${key}`,
        count
      });
    }

    if (trulyDangerous.length > 0) {
      const hasCritical = trulyDangerous.some(d => ['/Launch', '/JavaScript', '/JS', '/EmbeddedFile'].includes(d.key));
      report.score += hasCritical ? 30 : 15;
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 4 – Metadata Anomalies
   * ────────────────────────────────────────────── */
  _checkMetadataAnomalies(report) {
    const meta = report.metadata;
    let anomalies = 0;

    // Missing creator
    if (!meta.creator && !meta.producer) {
      report.findings.push({
        check: 'Metadata Anomaly',
        severity: 'medium',
        message: 'PDF has no Creator or Producer metadata — may be auto-generated by a tool'
      });
      anomalies++;
    }

    // Suspicious creator names
    const suspiciousCreators = ['metasploit', 'msfvenom', 'cobalt', 'exploit', 'payload', 'backdoor', 'rat'];
    const creator = (meta.creator || '').toLowerCase();
    const producer = (meta.producer || '').toLowerCase();
    for (const s of suspiciousCreators) {
      if (creator.includes(s) || producer.includes(s)) {
        report.findings.push({
          check: 'Metadata Anomaly',
          severity: 'critical',
          message: `Creator/Producer contains suspicious tool name: "${s}"`
        });
        anomalies += 3;
      }
    }

    // Creation date in the future
    if (meta.creationDate) {
      try {
        const created = new Date(meta.creationDate);
        if (created > new Date()) {
          report.findings.push({
            check: 'Metadata Anomaly',
            severity: 'medium',
            message: 'PDF creation date is in the future — possible date spoofing'
          });
          anomalies++;
        }
      } catch { /* ignore parse errors */ }
    }

    if (anomalies > 0) {
      report.score += Math.min(anomalies * 5, 20);
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 5 – Obfuscation Patterns
   * ────────────────────────────────────────────── */
  _checkObfuscation(raw, report) {
    let obfuscationScore = 0;

    // Check suspicious stream filters
    for (const filter of this.suspiciousFilters) {
      const regex = new RegExp(filter.replace('/', '\\/'), 'gi');
      const matches = raw.match(regex);
      if (matches && matches.length > 2) {
        report.findings.push({
          check: 'Obfuscation',
          severity: 'high',
          message: `Excessive use of stream filter ${filter} (${matches.length}×)`
        });
        obfuscationScore += 10;
      }
    }

    // Check for excessive hex encoding
    const hexChunks = raw.match(/<[0-9A-Fa-f]{20,}>/g);
    if (hexChunks && hexChunks.length > 5) {
      report.findings.push({
        check: 'Obfuscation',
        severity: 'medium',
        message: `${hexChunks.length}× large hex-encoded data blocks detected`
      });
      obfuscationScore += 10;
    }

    // Check for char code obfuscation patterns
    const charCodes = raw.match(/\\[0-9]{3}/g);
    if (charCodes && charCodes.length > 50) {
      report.findings.push({
        check: 'Obfuscation',
        severity: 'medium',
        message: `High density of octal character escapes (${charCodes.length}×) — possible obfuscation`
      });
      obfuscationScore += 10;
    }

    report.score += Math.min(obfuscationScore, 25);
  }

  /* ─────────────────────────────────────────────
   * CHECK 6 – Content Heuristics
   * ────────────────────────────────────────────── */
  _checkContentHeuristics(text, report) {
    const lower = text.toLowerCase();
    let hits = 0;

    for (const keyword of this.suspiciousKeywords) {
      if (lower.includes(keyword)) {
        report.findings.push({
          check: 'Content Heuristics',
          severity: 'medium',
          message: `Suspicious phrase found in CV text: "${keyword}"`
        });
        hits++;
      }
    }

    if (hits > 0) {
      report.score += Math.min(hits * 5, 20);
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 7 – Structure Analysis
   * ────────────────────────────────────────────── */
  _checkStructure(buffer, pdfData, report) {
    const sizeKB = buffer.length / 1024;
    const pages = pdfData.numpages || 1;
    const sizePerPage = sizeKB / pages;

    // A normal text-based resume is typically < 500 KB per page
    if (sizePerPage > 3000) {
      report.findings.push({
        check: 'Structure Analysis',
        severity: 'medium',
        message: `Unusually large file size per page (${Math.round(sizePerPage)} KB/page) — may contain hidden payloads`
      });
      report.score += 10;
    }

    // Very small file claiming many pages
    if (pages > 20 && sizeKB < 50) {
      report.findings.push({
        check: 'Structure Analysis',
        severity: 'medium',
        message: `Claims ${pages} pages but only ${Math.round(sizeKB)} KB — likely crafted/malformed`
      });
      report.score += 10;
    }

    // Count obj definitions in raw stream
    const objCount = (buffer.toString('latin1').match(/\d+ \d+ obj/g) || []).length;
    if (objCount > pages * 100) {
      report.findings.push({
        check: 'Structure Analysis',
        severity: 'medium',
        message: `Excessive object count (${objCount} objects for ${pages} pages) — may contain hidden streams`
      });
      report.score += 10;
    }
  }

  /* ─────────────────────────────────────────────
   * Helpers
   * ────────────────────────────────────────────── */
  _extractMetadata(pdfData) {
    const info = pdfData.info || {};
    return {
      title: info.Title || null,
      author: info.Author || null,
      subject: info.Subject || null,
      creator: info.Creator || null,
      producer: info.Producer || null,
      creationDate: info.CreationDate || null,
      modDate: info.ModDate || null,
      pdfVersion: pdfData.version || null
    };
  }

  _riskLevel(score) {
    if (score <= 5)  return 'safe';
    if (score <= 20) return 'low';
    if (score <= 45) return 'medium';
    if (score <= 70) return 'high';
    return 'critical';
  }

  _buildSummary(report) {
    const count = report.findings.length;
    if (count === 0) return 'No threats detected. This PDF appears to be a clean resume.';

    const criticals = report.findings.filter(f => f.severity === 'critical').length;
    const highs = report.findings.filter(f => f.severity === 'high').length;

    if (criticals > 0) {
      return `⚠️ CRITICAL THREAT – ${criticals} critical and ${highs} high-severity findings detected. This PDF is highly likely to be malicious.`;
    }
    if (report.score > 45) {
      return `🔶 HIGH RISK – ${count} suspicious indicators found. This PDF should be quarantined and reviewed manually.`;
    }
    if (report.score > 20) {
      return `🟡 MODERATE RISK – ${count} minor anomalies detected. Proceed with caution.`;
    }
    return `🟢 LOW RISK – ${count} minor observation(s). Likely safe but flagged for review.`;
  }

  _buildRecommendations(report) {
    const recs = [];
    const checks = new Set(report.findings.map(f => f.check));

    if (checks.has('JavaScript Detection')) {
      recs.push('🚫 Do NOT open this PDF in Adobe Acrobat. Use a sandboxed PDF viewer.');
    }
    if (checks.has('Embedded Objects')) {
      recs.push('🔒 Quarantine this file. Embedded objects may execute payloads on open.');
    }
    if (checks.has('Suspicious URLs')) {
      recs.push('🌐 Do not click any links in this PDF. Verify URLs manually.');
    }
    if (checks.has('Obfuscation')) {
      recs.push('🔍 Submit this file to VirusTotal or a sandbox for deeper analysis.');
    }
    if (checks.has('Content Heuristics')) {
      recs.push('📝 Review the text content carefully — contains social engineering language.');
    }
    if (report.riskLevel === 'safe') {
      recs.push('✅ No immediate threats detected. Standard resume processing can proceed.');
    }

    return recs;
  }
}

module.exports = PDFAnalyzer;
