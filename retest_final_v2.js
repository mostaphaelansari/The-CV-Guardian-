require('dotenv').config();
const PDFAnalyzer = require('./analyzer/pdfAnalyzer');
const fs = require('fs');
const path = require('path');

async function analyze() {
    const logFile = path.join(__dirname, 'retest_debug.log');
    const log = (msg) => {
        console.log(msg);
        fs.appendFileSync(logFile, msg + '\n');
    };

    // Clear log
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);

    const filePath = path.join(__dirname, 'data', 'CV-selma-koudia-ECC.pdf');
    if (!fs.existsSync(filePath)) {
        log('File not found: ' + filePath);
        return;
    }

    log(`Analyzing file: ${filePath}`);
    const buffer = fs.readFileSync(filePath);
    const analyzer = new PDFAnalyzer();

    // Hook console.log to capture analyzer logs too
    const originalLog = console.log;
    console.log = function (...args) {
        const msg = args.map(a => (typeof a === 'object' ? JSON.stringify(a) : a)).join(' ');
        fs.appendFileSync(logFile, '[Analyzer] ' + msg + '\n');
        originalLog.apply(console, args);
    };

    try {
        const report = await analyzer.analyze(buffer, 'CV-selma-koudia-ECC.pdf');

        log('----- ANALYSIS REPORT -----');
        log(`Final Score: ${report.score}`);
        log(`Risk Level: ${report.riskLevel}`);
        log(`Page Count: ${report.pageCount}`);
        log('Findings:');
        report.findings.forEach(f => {
            log(`- [${f.severity.toUpperCase()}] ${f.check}: ${f.message}`);
        });

    } catch (err) {
        log('Analysis failed: ' + err.stack);
    }
}

analyze();
