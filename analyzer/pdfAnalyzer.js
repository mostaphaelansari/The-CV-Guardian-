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

    // ── SQL Injection patterns ──
    this.sqlInjectionPatterns = [
      { pattern: /'\s*OR\s+'[^']*'\s*=\s*'[^']*'/gi, label: 'SQL tautology injection (\' OR \'x\'=\'x)' },
      { pattern: /'\s*OR\s+\d+\s*=\s*\d+/gi, label: 'SQL tautology injection (\' OR 1=1)' },
      { pattern: /UNION\s+SELECT/gi, label: 'UNION SELECT injection' },
      { pattern: /DROP\s+TABLE/gi, label: 'DROP TABLE injection' },
      { pattern: /INSERT\s+INTO/gi, label: 'INSERT INTO injection' },
      { pattern: /DELETE\s+FROM/gi, label: 'DELETE FROM injection' },
      { pattern: /;\s*--/g, label: 'SQL comment termination' },
      { pattern: /--\s+\w/g, label: 'SQL line comment' },
      { pattern: /\/\*.*?\*\//gs, label: 'SQL block comment' },
      { pattern: /EXEC\s*\(/gi, label: 'EXEC() call' },
      { pattern: /xp_cmdshell/gi, label: 'xp_cmdshell execution' },
      { pattern: /WAITFOR\s+DELAY/gi, label: 'SQL time-based injection (WAITFOR)' },
      { pattern: /BENCHMARK\s*\(/gi, label: 'SQL time-based injection (BENCHMARK)' }
    ];

    // ── XSS / HTML Injection patterns ──
    this.xssPatterns = [
      { pattern: /<script[^>]*>/gi, label: '<script> tag' },
      { pattern: /<\/script>/gi, label: '</script> closing tag' },
      { pattern: /<svg[^>]*\s+onload\s*=/gi, label: '<svg onload=> event handler' },
      { pattern: /<img[^>]*\s+onerror\s*=/gi, label: '<img onerror=> event handler' },
      { pattern: /on(load|error|click|mouseover|focus|blur)\s*=\s*["']?[^"'\s>]+/gi, label: 'Inline event handler attribute' },
      { pattern: /javascript\s*:/gi, label: 'javascript: URI scheme' },
      { pattern: /data\s*:\s*text\/html/gi, label: 'data:text/html URI' },
      { pattern: /<iframe[^>]*>/gi, label: '<iframe> tag' },
      { pattern: /<object[^>]*>/gi, label: '<object> tag' },
      { pattern: /<embed[^>]*>/gi, label: '<embed> tag' },
      { pattern: /expression\s*\(/gi, label: 'CSS expression() injection' },
      { pattern: /document\.cookie/gi, label: 'document.cookie access' },
      { pattern: /document\.location/gi, label: 'document.location access' },
      { pattern: /window\.location/gi, label: 'window.location access' }
    ];

    // ── Command Injection patterns ──
    this.commandInjectionPatterns = [
      { pattern: /rm\s+-rf\s+\//g, label: 'rm -rf / (destructive command)' },
      { pattern: /cmd\.exe\s+\/c/gi, label: 'cmd.exe /c (Windows command execution)' },
      { pattern: /\|\s*(cat|ls|dir|whoami|id|passwd|shadow)\b/gi, label: 'Pipe to system command' },
      { pattern: /;\s*(wget|curl|nc|netcat|bash|sh|python|perl|ruby)\b/gi, label: 'Chained shell command' },
      { pattern: /&&\s*(wget|curl|rm|chmod|chown|mkfs)\b/gi, label: 'Chained destructive command' },
      { pattern: /\$\(.*\)/g, label: 'Command substitution $()' },
      { pattern: /`[^`]*`/g, label: 'Backtick command substitution' },
      { pattern: /\/etc\/(passwd|shadow|hosts)/g, label: 'Sensitive file path reference' },
      { pattern: /\bnet\s+user\b/gi, label: 'Windows net user command' },
      { pattern: /\breg\s+(add|delete|query)\b/gi, label: 'Windows registry command' }
    ];

    // ── Prompt Injection patterns ──
    this.promptInjectionPatterns = [
      { pattern: /ignore\s+(all\s+)?previous\s+instructions/gi, label: 'Prompt injection: ignore previous instructions' },
      { pattern: /reveal\s+(the\s+)?(system\s+)?prompt/gi, label: 'Prompt injection: reveal system prompt' },
      { pattern: /disregard\s+(all\s+)?(prior|previous|above)/gi, label: 'Prompt injection: disregard prior instructions' },
      { pattern: /you\s+are\s+now\s+(a|an|the)/gi, label: 'Prompt injection: role override' },
      { pattern: /new\s+instructions?\s*:/gi, label: 'Prompt injection: new instructions directive' },
      { pattern: /act\s+as\s+(a|an|if)/gi, label: 'Prompt injection: act-as directive' },
      { pattern: /forget\s+(everything|all|your)/gi, label: 'Prompt injection: forget directive' },
      { pattern: /override\s+(previous|safety|security)/gi, label: 'Prompt injection: override directive' }
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

      // ── Run all 10 checks ──
      this._checkJavaScript(rawBuffer, report);
      this._checkSuspiciousURLs(rawText, rawBuffer, report);
      this._checkEmbeddedObjects(rawBuffer, report);
      this._checkMetadataAnomalies(report);
      this._checkObfuscation(rawBuffer, report);
      this._checkContentHeuristics(rawText, report);
      this._checkStructure(fileBuffer, pdfData, report);
      this._checkInjectionPatterns(rawText, report);
      this._checkEncodedPayloads(rawText, report);
      this._checkUnicodeObfuscation(rawText, report);

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
      { pattern: /\/JavaScript/gi, label: '/JavaScript action' },
      { pattern: /\/JS\s/gi, label: '/JS action' },
      { pattern: /eval\s*\(/gi, label: 'eval() call' },
      { pattern: /app\.\w+/gi, label: 'Acrobat app object reference' },
      { pattern: /this\.submitForm/gi, label: 'submitForm call' },
      { pattern: /this\.exportDataObject/gi, label: 'exportDataObject call' },
      { pattern: /util\.printf/gi, label: 'util.printf (potential heap spray)' },
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
   * CHECK 8 – Injection Pattern Detection
   * ────────────────────────────────────────────── */
  _checkInjectionPatterns(text, report) {
    const categories = [
      { name: 'SQL Injection', patterns: this.sqlInjectionPatterns },
      { name: 'XSS / HTML Injection', patterns: this.xssPatterns },
      { name: 'Command Injection', patterns: this.commandInjectionPatterns },
      { name: 'Prompt Injection', patterns: this.promptInjectionPatterns }
    ];

    let categoriesHit = 0;

    for (const { name, patterns } of categories) {
      let categoryFindings = 0;
      for (const { pattern, label } of patterns) {
        // Reset regex lastIndex for global patterns
        pattern.lastIndex = 0;
        const matches = text.match(pattern);
        if (matches && matches.length > 0) {
          report.findings.push({
            check: 'Injection Detection',
            severity: 'high',
            message: `${name}: ${label} (${matches.length}× found)`,
            count: matches.length,
            category: name
          });
          categoryFindings++;
        }
      }
      if (categoryFindings > 0) categoriesHit++;
    }

    if (categoriesHit > 0) {
      report.score += Math.min(categoriesHit * 10, 35);
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 9 – Encoded Payload Detection
   * ────────────────────────────────────────────── */
  _checkEncodedPayloads(text, report) {
    let findings = 0;

    // Detect base64-encoded strings (minimum 20 chars to avoid false positives)
    const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const b64Matches = text.match(base64Regex) || [];

    for (const match of b64Matches) {
      try {
        const decoded = Buffer.from(match, 'base64').toString('utf-8');
        // Check if decoded content contains recognisable attack patterns
        const dangerousDecoded = [
          /<script/i, /SELECT\s/i, /DROP\s/i, /cmd\.exe/i,
          /\/bin\/sh/i, /eval\s*\(/i, /rm\s+-rf/i, /powershell/i,
          /<svg/i, /<iframe/i, /javascript:/i, /onerror\s*=/i
        ];
        for (const dp of dangerousDecoded) {
          if (dp.test(decoded)) {
            report.findings.push({
              check: 'Encoded Payload',
              severity: 'high',
              message: `Base64-encoded attack payload detected — decodes to suspicious content: "${decoded.substring(0, 60)}…"`,
              category: 'Encoded Payload'
            });
            findings++;
            break;
          }
        }
      } catch { /* not valid base64 – ignore */ }
    }

    // Also flag high number of base64-like strings
    if (b64Matches.length > 3) {
      report.findings.push({
        check: 'Encoded Payload',
        severity: 'medium',
        message: `${b64Matches.length} base64-encoded strings found in CV text — unusual for a resume`,
        category: 'Encoded Payload'
      });
      findings++;
    }

    if (findings > 0) {
      report.score += Math.min(findings * 10, 20);
    }
  }

  /* ─────────────────────────────────────────────
   * CHECK 10 – Unicode Obfuscation Detection
   * ────────────────────────────────────────────── */
  _checkUnicodeObfuscation(text, report) {
    // Detect fullwidth Unicode characters (U+FF01–U+FF5E)
    const fullwidthRegex = /[\uFF01-\uFF5E]{2,}/g;
    const fwMatches = text.match(fullwidthRegex) || [];

    if (fwMatches.length === 0) return;

    // Normalize fullwidth → ASCII and check for injection patterns
    const normalised = text.replace(/[\uFF01-\uFF5E]/g, ch =>
      String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)
    );

    const obfuscatedInjections = [
      { pattern: /UNION\s+SELECT/gi, label: 'UNION SELECT (Unicode-obfuscated)' },
      { pattern: /DROP\s+TABLE/gi, label: 'DROP TABLE (Unicode-obfuscated)' },
      { pattern: /SELECT\s+FROM/gi, label: 'SELECT FROM (Unicode-obfuscated)' },
      { pattern: /<script/gi, label: '<script> (Unicode-obfuscated)' },
      { pattern: /rm\s+-rf/gi, label: 'rm -rf (Unicode-obfuscated)' },
      { pattern: /cmd\.exe/gi, label: 'cmd.exe (Unicode-obfuscated)' }
    ];

    let found = false;
    for (const { pattern, label } of obfuscatedInjections) {
      if (pattern.test(normalised)) {
        report.findings.push({
          check: 'Unicode Obfuscation',
          severity: 'high',
          message: `Obfuscated attack pattern detected via fullwidth Unicode: ${label}`,
          category: 'Unicode Obfuscation'
        });
        found = true;
      }
    }

    if (!found && fwMatches.length > 0) {
      report.findings.push({
        check: 'Unicode Obfuscation',
        severity: 'medium',
        message: `${fwMatches.length} fullwidth Unicode sequences found — may be used to evade text-based filters`,
        category: 'Unicode Obfuscation'
      });
    }

    report.score += found ? 15 : 5;
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
    if (score <= 5) return 'safe';
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
    if (checks.has('Injection Detection')) {
      recs.push('💉 CV contains code-injection patterns (SQL/XSS/command/prompt). Treat as hostile input — do NOT process through any automated pipelines without sanitisation.');
    }
    if (checks.has('Encoded Payload')) {
      recs.push('🔐 Base64-encoded or obfuscated payloads detected. Decoded content may contain executable attack code.');
    }
    if (checks.has('Unicode Obfuscation')) {
      recs.push('🔤 Fullwidth Unicode obfuscation detected — attacker may be trying to bypass text-based security filters.');
    }
    if (report.riskLevel === 'safe') {
      recs.push('✅ No immediate threats detected. Standard resume processing can proceed.');
    }

    return recs;
  }
}

module.exports = PDFAnalyzer;
