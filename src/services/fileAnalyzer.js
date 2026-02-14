/**
 * Main File Analyzer – performs security checks on uploaded CV/resume files (PDF, DOCX, TXT).
 * Returns a structured threat report with score, risk level, findings, and recommendations.
 */
class FileAnalyzer {

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
            { pattern: /ignore\s+(all\s+)?(previous|prior|preceding|above)\s+(instructions|rules|guidelines|constraints)/gi, label: 'ignore previous instructions' },
            { pattern: /disregard\s+(all\s+)?(previous|prior|above|safety|security)\s*(instructions|rules|guidelines|constraints)?/gi, label: 'disregard instructions/constraints' },
            { pattern: /reveal\s+(the\s+)?(system\s+)?(prompt|config|configuration|keys?|secrets?|data|schema|variables?|policies|embeddings)/gi, label: 'reveal sensitive information' },
            { pattern: /override\s+(previous|prior|safety|security|all)\s*(instructions|rules|constraints)?/gi, label: 'override directive' },
            { pattern: /you\s+are\s+now\s+(a|an|the|in)/gi, label: 'role/mode override' },
            { pattern: /act\s+as\s+(a|an|the|if)\b/gi, label: 'act-as directive' },
            { pattern: /new\s+instructions?\s*:/gi, label: 'new instructions directive' },
            { pattern: /forget\s+(everything|all|your|previous|prior)/gi, label: 'forget directive' },
            { pattern: /developer\s+mode/gi, label: 'developer mode activation' },
            { pattern: /execute\s+(the\s+)?following\s+(instruction|command|code)/gi, label: 'execute following instruction' },
            { pattern: /higher\s+priority\s+(than|over)/gi, label: 'priority escalation' },
            { pattern: /stop\s+(parsing|processing|reading|analyzing)/gi, label: 'stop processing directive' },
            { pattern: /print\s+(internal|hidden|system|secret|private)/gi, label: 'print internal data' },
            { pattern: /display\s+(api|secret|private|internal|hidden)\s*(keys?|data|info|tokens?)?/gi, label: 'display sensitive data' },
            { pattern: /return\s+(all\s+)?(environment|env|hidden|stored|internal|database|system)\s*(variables?|data|schema|config|embeddings|info)?/gi, label: 'return internal data' },
            { pattern: /provide\s+(stored|hidden|internal|secret|private)\s*(data|embeddings|info|keys?|tokens?)?/gi, label: 'provide stored data' },
            { pattern: /data\s+exfiltration/gi, label: 'data exfiltration reference' },
            { pattern: /chain[- ]?of[- ]?thought/gi, label: 'chain-of-thought extraction' },
            { pattern: /instruction[- ]?(priority|override|hierarchy)/gi, label: 'instruction priority manipulation' },
            { pattern: /jailbreak/gi, label: 'jailbreak attempt' },
            { pattern: /DAN\s+(mode|prompt)/gi, label: 'DAN jailbreak' },
            { pattern: /bypass\s+(safety|security|filter|guard|content\s+policy)/gi, label: 'bypass safety filters' }
        ];
    }

    /**
     * Analyse a file buffer and return a threat report.
     * @param {Buffer} fileBuffer – raw file bytes
     * @param {string} fileName  – original file name
     * @param {string} mimeType  – file mime type
     * @returns {Promise<object>} threat report
     */
    async analyze(fileBuffer, fileName, mimeType) {
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

        let rawText = '';
        const rawBuffer = fileBuffer.toString('latin1'); // For binary pattern matching

        try {
            // ── Extract Text & Metadata (via Sandbox) ──
            const sandboxService = require('./sandboxService');
            let parseResult;

            try {
                parseResult = await sandboxService.parseFile(fileBuffer, fileName, mimeType);
            } catch (sbError) {
                throw new Error(`Sandbox unavailable: ${sbError.message}`);
            }

            rawText = parseResult.text || '';
            report.pageCount = parseResult.pageCount || 0;
            report.metadata = parseResult.metadata || {};

            // ── Handle partial parse (sandbox returned OK but parser failed internally) ──
            if (parseResult.parseError) {
                report.findings.push({
                    check: 'File Parsing',
                    severity: 'medium',
                    message: `File could not be fully parsed: ${parseResult.parseError}. Some checks may be limited.`
                });
                report.score += 5;
            }

            if (mimeType === 'application/pdf') {
                // PDF-specific checks using the raw buffer (safe regex)
                const pdfData = {
                    numpages: report.pageCount,
                    info: report.metadata,
                    text: rawText
                };

                this._checkStructure(fileBuffer, pdfData, report);
                this._checkJavaScript(rawBuffer, report);
                this._checkEmbeddedObjects(rawBuffer, report);
                this._checkMetadataAnomalies(report);
                this._checkObfuscation(rawBuffer, report);

            } else if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') { // DOCX
                if (rawText.length === 0 && parseResult.error) {
                    report.findings.push({
                        check: 'DOCX Structure',
                        severity: 'low',
                        message: `DOCX parsing warning: ${parseResult.error}`
                    });
                }
            } else if (mimeType === 'text/plain') { // TXT
                // Text checks
            }

            // ── Universal Text Checks (All formats) ──
            this._checkPageCount(report);
            this._checkSuspiciousURLs(rawText, rawBuffer, report);
            this._checkContentHeuristics(rawText, report);
            this._checkInjectionPatterns(rawText, report);
            this._checkEncodedPayloads(rawText, report);
            this._checkUnicodeObfuscation(rawText, report);
            this._scoreAIGeneration(rawText, report);
            await this._analyzeContext(rawText, report);

        } catch (err) {
            report.findings.push({
                check: 'File Parsing',
                severity: 'medium',
                message: `Failed to parse file: ${err.message}. Analysis may be incomplete.`
            });
            report.score += 10;
        }

        // ── Finalise score & risk level ──
        // Only security-critical findings (not bot-detection) should trigger the score floor
        const securityFindings = report.findings.filter(f => f.check !== 'AI-Generation Analysis');
        const hasCritical = securityFindings.some(f => f.severity === 'critical');
        const hasHighSecurity = securityFindings.some(f => f.severity === 'high');

        if (hasCritical) {
            report.score = Math.max(report.score, 90);
            report.riskLevel = 'critical';
        } else if (hasHighSecurity) {
            report.score = Math.max(report.score, 75);
            report.riskLevel = 'high';
        } else {
            report.score = Math.min(report.score, 100);
            report.riskLevel = this._riskLevel(report.score);
        }

        report.summary = this._buildSummary(report);
        report.recommendations = this._buildRecommendations(report);

        return report;
    }

    _estimatePageCount(text) {
        // Estimate 3000 chars per page
        return Math.ceil(text.length / 3000) || 1;
    }

    _checkPageCount(report) {
        if (report.pageCount > 6) {
            report.findings.push({
                check: 'Policy Violation',
                severity: 'medium',
                message: `Document exceeds maximum page limit (6 pages). detected: ${report.pageCount} pages.`
            });
            report.score += 20;
        }
    }

    /* ─────────────────────────────────────────────
     * CHECK 1 – JavaScript Detection (PDF ONLY)
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
     * CHECK 3 – Embedded Objects & Auto-Actions (PDF ONLY)
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
     * CHECK 4 – Metadata Anomalies (PDF ONLY)
     * ────────────────────────────────────────────── */
    _checkMetadataAnomalies(report) {
        const meta = report.metadata;
        let anomalies = 0;

        // Missing creator — possible indicator of bot/auto-generated CV
        if (!meta.creator && !meta.producer) {
            report.findings.push({
                check: 'AI-Generation Analysis',
                severity: 'medium',
                message: 'PDF has no Creator or Producer metadata — may be auto-generated by a bot or online tool'
            });
            anomalies += 1;
        }

        // ── Known bot / AI / online resume-builder generators ──
        const botGenerators = [
            'chatgpt', 'openai', 'gpt-4', 'gpt-3', 'claude', 'gemini', 'copilot',
            'jasper', 'writesonic', 'copy.ai', 'grammarly',
            'canva', 'resume.io', 'resumebuilder', 'novoresume', 'zety',
            'kickresume', 'enhancv', 'visualcv', 'resume-now', 'livecareer',
            'myperfectresume', 'resumegenius', 'cvmaker', 'flowcv', 'rxresu',
            'overleaf', 'sharelatex',
            'wkhtmltopdf', 'puppeteer', 'headless chrome', 'phantomjs',
            'fpdf', 'reportlab', 'pdfkit', 'jspdf', 'itext',
            'docraptor', 'prince', 'weasyprint'
        ];
        const creator = (meta.creator || '').toLowerCase();
        const producer = (meta.producer || '').toLowerCase();
        const creatorProducer = creator + ' ' + producer;

        for (const bot of botGenerators) {
            if (creatorProducer.includes(bot)) {
                report.findings.push({
                    check: 'AI-Generation Analysis',
                    severity: 'high',
                    message: `PDF created by known automated tool: "${bot}" — CV is likely bot-generated`
                });
                anomalies += 2;
                break; // one match is enough
            }
        }

        // Suspicious creator names (malware tools)
        const suspiciousCreators = ['metasploit', 'msfvenom', 'cobalt', 'exploit', 'payload', 'backdoor', 'rat'];
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
            report.score += Math.min(anomalies * 8, 35);
        }
    }

    /* ─────────────────────────────────────────────
     * CHECK 5 – Obfuscation Patterns (PDF ONLY)
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
     * CHECK 7 – Structure Analysis (PDF ONLY)
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
            { name: 'SQL Injection', patterns: this.sqlInjectionPatterns, severity: 'critical', score: 30 },
            { name: 'XSS / HTML Injection', patterns: this.xssPatterns, severity: 'critical', score: 30 },
            { name: 'Command Injection', patterns: this.commandInjectionPatterns, severity: 'critical', score: 40 },
            { name: 'Prompt Injection', patterns: this.promptInjectionPatterns, severity: 'critical', score: 40 }
        ];

        let totalScoreIncrease = 0;
        let totalFindings = 0;

        for (const { name, patterns, severity, score } of categories) {
            let categoryFindings = 0;
            for (const { pattern, label } of patterns) {
                // Reset regex lastIndex for global patterns
                pattern.lastIndex = 0;
                const matches = text.match(pattern);
                if (matches && matches.length > 0) {
                    report.findings.push({
                        check: 'Injection Detection',
                        severity: severity,
                        message: `${name}: ${label} (${matches.length}× found)`,
                        count: matches.length,
                        category: name
                    });
                    categoryFindings++;
                }
            }
            if (categoryFindings > 0) {
                totalScoreIncrease += score;
                totalFindings += categoryFindings;
            }
        }

        // Apply score increase (capped at 75 to allow other checks to contribute, but high enough to be distinct)
        if (totalScoreIncrease > 0) {
            report.score += Math.min(totalScoreIncrease, 75);
        }

        // Density bonus: many injection findings in one document strongly suggests a weaponised file
        if (totalFindings >= 5) {
            report.findings.push({
                check: 'Injection Detection',
                severity: 'critical',
                message: `High density of injection patterns: ${totalFindings} distinct patterns detected — document is very likely weaponised`,
                count: totalFindings,
                category: 'Density'
            });
            report.score += 25; // Additional boost for density
        }
    }

    /* ─────────────────────────────────────────────
     * CHECK 9 – Encoded Payload Detection
     * ────────────────────────────────────────────── */
    _checkEncodedPayloads(text, report) {
        let findings = 0;

        // Detect base64-encoded strings (minimum 40 chars, must end with = or ==, to avoid false positives on normal text)
        const base64Regex = /[A-Za-z0-9+\/]{40,}={1,2}/g;
        const b64Matches = text.match(base64Regex) || [];

        for (const match of b64Matches) {
            try {
                // Verify it's actually valid base64 (decoded length should be ~75% of encoded)
                const decoded = Buffer.from(match, 'base64').toString('utf-8');
                const ratio = decoded.length / match.length;
                if (ratio < 0.5 || ratio > 0.85) continue; // not real base64

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
                            severity: 'critical',
                            message: `Base64-encoded attack payload detected — decodes to suspicious content: "${decoded.substring(0, 60)}…"`,
                            category: 'Encoded Payload'
                        });
                        findings++;
                        break;
                    }
                }
            } catch { /* not valid base64 – ignore */ }
        }

        // Also flag high number of base64-like strings (only if many are found)
        if (b64Matches.length > 5) {
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
                    severity: 'critical',
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

    /* ══════════════════════════════════════════════════════
     * CHECK 11 – AI-Generation Risk Scoring Framework
     * 7 dimensions, each scored 0–5, total 0–50 (excl. cross-consistency)
     * ══════════════════════════════════════════════════════ */
    _scoreAIGeneration(text, report) {
        if (!text || text.length < 100) return;

        const lower = text.toLowerCase();
        const words = text.split(/\s+/).filter(w => w.length > 0);
        const wordCount = words.length;
        const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 5);

        const aiScore = {
            dimensions: {},
            total: 0,
            riskLabel: 'Likely Human'
        };

        // ═══════════════════════════════════════════
        // 1.1 – Buzzword Density (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['1.1_buzzword_density'] = this._aiBuzzwordDensity(lower, wordCount);

        // ═══════════════════════════════════════════
        // 1.2 – Sentence Uniformity (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['1.2_sentence_uniformity'] = this._aiSentenceUniformity(sentences);

        // ═══════════════════════════════════════════
        // 1.3 – Friction Absence (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['1.3_friction_absence'] = this._aiFrictionAbsence(lower, wordCount);

        // ═══════════════════════════════════════════
        // 2.1 – Tool Specificity (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['2.1_tool_specificity'] = this._aiToolSpecificity(lower, text);

        // ═══════════════════════════════════════════
        // 2.2 – Scale Realism (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['2.2_scale_realism'] = this._aiScaleRealism(lower, text);

        // ═══════════════════════════════════════════
        // 2.3 – Timeline Plausibility (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['2.3_timeline_plausibility'] = this._aiTimelinePlausibility(lower, text);

        // ═══════════════════════════════════════════
        // 4 – Stylometric Indicators (0–5)
        // ═══════════════════════════════════════════
        aiScore.dimensions['4.0_stylometric'] = this._aiStylometric(sentences, words);

        // ═══════════════════════════════════════════
        // 3 – Cross-Consistency (manual only)
        // ═══════════════════════════════════════════
        aiScore.dimensions['3.0_cross_consistency'] = null; // requires external data

        // ── Total ──
        aiScore.total = Object.values(aiScore.dimensions)
            .filter(v => v !== null)
            .reduce((sum, v) => sum + v, 0);

        // ── Risk label mapping ──
        if (aiScore.total >= 36) aiScore.riskLabel = 'Highly AI-Generated';
        else if (aiScore.total >= 26) aiScore.riskLabel = 'Likely AI-Assisted';
        else if (aiScore.total >= 16) aiScore.riskLabel = 'Mixed / Assisted';
        else aiScore.riskLabel = 'Likely Human';

        // ── Store on report ──
        report.aiScore = aiScore;

        // ── Map to findings and score contribution ──
        if (aiScore.total >= 36) {
            report.findings.push({
                check: 'AI-Generation Analysis',
                severity: 'high',
                message: `AI-generation risk: ${aiScore.total}/35 — ${aiScore.riskLabel}. This CV shows strong indicators of being entirely AI-generated.`,
                category: 'AI Detection'
            });
            report.score += 25;
        } else if (aiScore.total >= 26) {
            report.findings.push({
                check: 'AI-Generation Analysis',
                severity: 'high',
                message: `AI-generation risk: ${aiScore.total}/35 — ${aiScore.riskLabel}. Significant portions of this CV appear machine-written.`,
                category: 'AI Detection'
            });
            report.score += 15;
        } else if (aiScore.total >= 16) {
            report.findings.push({
                check: 'AI-Generation Analysis',
                severity: 'medium',
                message: `AI-generation risk: ${aiScore.total}/35 — ${aiScore.riskLabel}. Some sections may have been AI-assisted.`,
                category: 'AI Detection'
            });
            report.score += 5;
        }
        // 0–15: Likely Human → no finding, no score penalty
    }

    /* ─── 1.1 Buzzword Density ──────────────────── */
    _aiBuzzwordDensity(lower, wordCount) {
        const buzzPhrases = [
            'proven track record', 'results-driven', 'dynamic environment',
            'leveraged synergies', 'synergy', 'paradigm', 'leverage',
            'spearhead', 'orchestrate', 'streamline', 'optimize', 'innovate',
            'disruption', 'scalable', 'holistic', 'robust', 'cutting-edge',
            'best-in-class', 'world-class', 'thought leader', 'value-add',
            'stakeholder', 'ecosystem', 'bandwidth', 'highly motivated',
            'passionate about', 'committed to continuous', 'detail-oriented',
            'self-starter', 'team player', 'go-getter', 'proactive',
            'results-oriented', 'fast-paced', 'cross-functional',
            'drive growth', 'deliver results', 'strong work ethic',
            'excellent communication', 'interpersonal skills'
        ];

        let hits = 0;
        for (const phrase of buzzPhrases) {
            if (lower.includes(phrase)) hits++;
        }

        if (wordCount < 50) return 0;
        const density = hits / (wordCount / 100); // hits per 100 words

        if (density >= 4) return 5;
        if (density >= 3) return 4;
        if (density >= 2) return 3;
        if (density >= 1) return 2;
        if (hits >= 1) return 1;
        return 0;
    }

    /* ─── 1.2 Sentence Uniformity ───────────────── */
    _aiSentenceUniformity(sentences) {
        if (sentences.length < 5) return 0;

        // Measure sentence-length variance
        const lengths = sentences.map(s => s.trim().split(/\s+/).length);
        const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
        const variance = lengths.reduce((sum, l) => sum + Math.pow(l - mean, 2), 0) / lengths.length;
        const cv = mean > 0 ? Math.sqrt(variance) / mean : 0; // coefficient of variation

        // Check structural repetition ("Led X to Y by Z" pattern)
        const structPatterns = sentences.map(s => {
            const t = s.trim().toLowerCase();
            // Extract first verb-like word
            const match = t.match(/^\s*(?:[-•]\s*)?(\w+ed|managed|led|developed|built|created|designed|implemented|spearheaded|leveraged|orchestrated|drove|delivered)/);
            return match ? match[1] : null;
        }).filter(Boolean);

        const uniqueStarters = new Set(structPatterns).size;
        const repetitionRatio = structPatterns.length > 0
            ? 1 - (uniqueStarters / structPatterns.length)
            : 0;

        // Low CV = uniform sentences (AI-like)
        let score = 0;
        if (cv < 0.2) score += 3;       // very uniform
        else if (cv < 0.35) score += 2;  // somewhat uniform
        else if (cv < 0.5) score += 1;   // mildly uniform

        if (repetitionRatio > 0.6) score += 2;
        else if (repetitionRatio > 0.4) score += 1;

        return Math.min(score, 5);
    }

    /* ─── 1.3 Friction Absence ──────────────────── */
    _aiFrictionAbsence(lower, wordCount) {
        if (wordCount < 50) return 0;

        // Words that indicate real-world friction (human CVs mention struggle)
        const frictionMarkers = [
            'debug', 'debugged', 'debugging', 'troubleshoot', 'troubleshooting',
            'fix', 'fixed', 'bug', 'bugs', 'workaround', 'constraint',
            'constraints', 'trade-off', 'tradeoff', 'trade-offs', 'limitation',
            'limitations', 'challenge', 'challenging', 'struggled', 'difficulty',
            'difficult', 'complex', 'complexity', 'refactor', 'refactored',
            'failed', 'failure', 'mistake', 'issue', 'issues', 'bottleneck',
            'technical debt', 'legacy', 'deprecated', 'breaking change',
            'outage', 'incident', 'root cause', 'postmortem', 'hotfix',
            'regression', 'edge case', 'edge cases', 'flaky'
        ];

        let frictionCount = 0;
        for (const marker of frictionMarkers) {
            if (lower.includes(marker)) frictionCount++;
        }

        // Polished-only phrases (AI loves these)
        const polishedPhrases = [
            'successfully', 'seamlessly', 'efficiently', 'effectively',
            'significantly improved', 'dramatically increased',
            'exceptional results', 'outstanding', 'flawlessly'
        ];

        let polishedCount = 0;
        for (const phrase of polishedPhrases) {
            if (lower.includes(phrase)) polishedCount++;
        }

        // High polished + low friction = AI-like
        if (frictionCount === 0 && polishedCount >= 3) return 5;
        if (frictionCount === 0 && polishedCount >= 1) return 4;
        if (frictionCount === 0) return 3;
        if (frictionCount <= 1 && polishedCount >= 2) return 2;
        if (frictionCount <= 2) return 1;
        return 0;
    }

    /* ─── 2.1 Tool Specificity ──────────────────── */
    _aiToolSpecificity(lower, text) {
        // Look for specific technical anchoring
        let specificitySignals = 0;

        // Version numbers (e.g., "Python 3.11", "Node 18", "React 18.2", "v2.3.1")
        const versionMatches = text.match(/\b(?:v?\d+\.\d+(?:\.\d+)?)\b/g) || [];
        if (versionMatches.length >= 3) specificitySignals += 2;
        else if (versionMatches.length >= 1) specificitySignals += 1;

        // Concrete libraries/tools (not just "Python" but "FastAPI", "SQLAlchemy", etc.)
        const concreteTools = [
            'fastapi', 'sqlalchemy', 'celery', 'redis', 'kafka', 'rabbitmq',
            'webpack', 'babel', 'eslint', 'prettier', 'jest', 'pytest',
            'terraform', 'ansible', 'kubernetes', 'k8s', 'helm', 'docker compose',
            'nginx', 'gunicorn', 'uvicorn', 'pm2', 'systemd', 'grafana',
            'prometheus', 'datadog', 'sentry', 'new relic', 'kibana',
            'elasticsearch', 'postgresql', 'mysql', 'dynamodb', 'cassandra',
            'scipy', 'pandas', 'numpy', 'scikit-learn', 'pytorch', 'tensorflow',
            'airflow', 'dbt', 'spark', 'flink', 'beam', 'mlflow'
        ];
        let toolHits = 0;
        for (const tool of concreteTools) {
            if (lower.includes(tool)) toolHits++;
        }
        if (toolHits >= 5) specificitySignals += 2;
        else if (toolHits >= 2) specificitySignals += 1;

        // Architecture references
        const archTerms = ['microservice', 'monolith', 'event-driven', 'pub/sub',
            'cqrs', 'saga pattern', 'circuit breaker', 'load balancer', 'cdn',
            'ci/cd', 'blue-green', 'canary deploy', 'service mesh', 'api gateway'];
        let archHits = 0;
        for (const term of archTerms) {
            if (lower.includes(term)) archHits++;
        }
        if (archHits >= 2) specificitySignals += 1;

        // Invert: high specificity = low score (human-like)
        // 0 specificity signals = score 5 (AI-like)
        const invertedScore = Math.max(0, 5 - specificitySignals);
        return invertedScore;
    }

    /* ─── 2.2 Scale Realism ─────────────────────── */
    _aiScaleRealism(lower, text) {
        let scaleSignals = 0;

        // Quantified metrics (users, requests, data volume)
        const scalePatterns = [
            /\b\d+[kKmMbB]?\s*(?:users|customers|clients|visitors|requests|rps|qps)/gi,
            /\b\d+(?:\.\d+)?\s*(?:TB|GB|MB|terabytes|gigabytes|petabytes)/gi,
            /\b\d+\s*(?:ms|milliseconds|seconds)\s*(?:latency|response|p99|p95|p50)/gi,
            /\b\d+%\s*(?:reduction|increase|improvement|uptime|availability)/gi,
            /\b\d+x\s*(?:faster|improvement|throughput|performance)/gi,
            /\$\d+[kKmMbB]?\b/g, // dollar amounts
            /\b\d+\s*(?:servers|nodes|instances|pods|containers|replicas)/gi
        ];

        for (const pattern of scalePatterns) {
            const matches = text.match(pattern);
            if (matches) scaleSignals += matches.length;
        }

        // Invert: more scale = lower score (human-like)
        if (scaleSignals >= 5) return 0;
        if (scaleSignals >= 3) return 1;
        if (scaleSignals >= 2) return 2;
        if (scaleSignals >= 1) return 3;
        return 5; // no measurable scale at all
    }

    /* ─── 2.3 Timeline Plausibility ─────────────── */
    _aiTimelinePlausibility(lower, text) {
        // Count distinct role/job entries
        const yearRanges = text.match(/\b20\d{2}\s*[-–—]\s*(?:20\d{2}|present|current|now)\b/gi) || [];
        const roleKeywords = (text.match(/\b(?:senior|junior|lead|principal|staff|intern|manager|director|architect|engineer|developer|analyst|consultant)\b/gi) || []);

        const uniqueRoles = new Set(roleKeywords.map(r => r.toLowerCase())).size;

        // Too many roles in a short period = suspicious
        // Heuristic: if they claim 6+ distinct roles, that's dense
        if (uniqueRoles >= 8 && yearRanges.length <= 3) return 5; // many roles, few time ranges
        if (uniqueRoles >= 6 && yearRanges.length <= 2) return 4;
        if (uniqueRoles >= 5 && yearRanges.length <= 2) return 3;

        // No timeline at all is also suspicious
        if (yearRanges.length === 0 && uniqueRoles >= 3) return 3;
        if (yearRanges.length === 0) return 2;

        return 0; // realistic timeline
    }

    /* ─── 4.0 Stylometric Indicators ────────────── */
    _aiStylometric(sentences, words) {
        if (sentences.length < 5 || words.length < 50) return 0;

        let score = 0;

        // ── Sentence length variance (low = AI-like) ──
        const sentLengths = sentences.map(s => s.trim().split(/\s+/).length);
        const meanLen = sentLengths.reduce((a, b) => a + b, 0) / sentLengths.length;
        const stdDev = Math.sqrt(sentLengths.reduce((sum, l) => sum + Math.pow(l - meanLen, 2), 0) / sentLengths.length);

        if (stdDev < 3) score += 2;       // very smooth (AI)
        else if (stdDev < 5) score += 1;   // somewhat smooth

        // ── Type-token ratio (lower = more repetitive vocabulary = AI-like) ──
        const lowerWords = words.map(w => w.toLowerCase().replace(/[^a-z]/g, '')).filter(w => w.length > 2);
        const uniqueWords = new Set(lowerWords).size;
        const ttr = lowerWords.length > 0 ? uniqueWords / lowerWords.length : 1;

        if (ttr < 0.35) score += 2;       // very repetitive vocabulary
        else if (ttr < 0.50) score += 1;   // somewhat repetitive

        // ── Burstiness: variation in sentence length differences (low = AI) ──
        if (sentLengths.length >= 3) {
            const diffs = [];
            for (let i = 1; i < sentLengths.length; i++) {
                diffs.push(Math.abs(sentLengths[i] - sentLengths[i - 1]));
            }
            const meanDiff = diffs.reduce((a, b) => a + b, 0) / diffs.length;
            const burstiness = Math.sqrt(diffs.reduce((sum, d) => sum + Math.pow(d - meanDiff, 2), 0) / diffs.length);

            if (burstiness < 2) score += 1; // very smooth transitions (AI)
        }

        return Math.min(score, 5);
    }

    /* ─────────────────────────────────────────────
     * NLP Context Analysis
     * ────────────────────────────────────────────── */
    async _analyzeContext(text, report) {
        if (!text || text.length < 50) return;

        try {
            const nlpService = require('./nlpService');
            const analysis = await nlpService.analyzeText(text.substring(0, 1000));

            if (analysis && Array.isArray(analysis) && analysis.length > 0) {
                const result = analysis[0];
                // Store as metadata only — generic sentiment models are not calibrated
                // for CV/resume text and produce false positives on professional language
                report.metadata.sentiment = result.label;
                report.metadata.sentimentScore = result.score;
            }
        } catch (err) {
            // NLP service unavailable — skip silently
        }

        // ── Threat-language check (independent of NLP model) ──
        // Only flag truly aggressive/threatening content that has no place in a CV
        // Uses word-boundary regex to avoid matching substrings (e.g. "kill" inside "skills")
        const lower = text.toLowerCase();
        const threatPatterns = [
            /\bi will hack\b/,
            /\bi will destroy\b/,
            /\bpay me or\b/,
            /\bsend bitcoin\b/,
            /\byour data will be\b/,
            /\bwe have your\b/,
            /\byou have been hacked\b/,
            /\bransom(?:ware)?\b/,
            /\bblackmail\b/,
            /\bi know where you live\b/,
            /\battack your\b/,
            /\blegal action against your company\b/,
            /\bpay the ransom\b/,
            /\bwe will leak\b/,
            /\bwe will publish\b/
        ];

        const threatHits = threatPatterns.filter(p => p.test(lower));
        if (threatHits.length >= 2) {
            report.findings.push({
                check: 'NLP Analysis',
                severity: 'high',
                message: `Threatening language detected in CV text — ${threatHits.length} threat patterns found. This is not normal CV content.`
            });
            report.score += 20;
        } else if (threatHits.length === 1) {
            report.findings.push({
                check: 'NLP Analysis',
                severity: 'medium',
                message: `Potentially threatening language detected in CV text. Manual review recommended.`
            });
            report.score += 5;
        }
    }

    /* ─────────────────────────────────────────────
     * Helpers
     * ────────────────────────────────────────────── */
    _extractPDFMetadata(pdfData) {
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
        if (count === 0) return 'No threats detected. This file appears to be a clean resume.';

        const criticals = report.findings.filter(f => f.severity === 'critical').length;
        const highs = report.findings.filter(f => f.severity === 'high').length;

        if (criticals > 0) {
            return `⚠️ CRITICAL THREAT – ${criticals} critical and ${highs} high-severity findings detected. This file is highly likely to be malicious.`;
        }
        if (report.score > 45) {
            return `🔶 HIGH RISK – ${count} suspicious indicators found. This file should be quarantined and reviewed manually.`;
        }
        if (report.score > 20) {
            return `🟡 MODERATE RISK – ${count} minor anomalies detected. Proceed with caution.`;
        }
        return `🟢 LOW RISK – ${count} minor observation(s). Likely safe but flagged for review.`;
    }

    _buildRecommendations(report) {
        const recs = [];
        const checks = new Set(report.findings.map(f => f.check));

        if (checks.has('AI-Generation Analysis')) {
            recs.push('🤖 This CV appears to be bot-generated or created by an AI tool. Request the candidate to submit an original, human-written CV. Consider verifying authorship during the interview process.');
        }
        if (checks.has('JavaScript Detection')) {
            recs.push('🚫 Do NOT open this PDF in Adobe Acrobat. Use a sandboxed PDF viewer.');
        }
        if (checks.has('Embedded Objects')) {
            recs.push('🔒 Quarantine this file. Embedded objects may execute payloads on open.');
        }
        if (checks.has('Suspicious URLs')) {
            recs.push('🌐 Do not click any links in this file. Verify URLs manually.');
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
        if (checks.has('Policy Violation')) {
            recs.push('⚠️ Document exceeds page limit policy.');
        }
        if (report.riskLevel === 'safe') {
            recs.push('✅ No immediate threats detected. Standard resume processing can proceed.');
        }

        return recs;
    }
}

module.exports = FileAnalyzer;
