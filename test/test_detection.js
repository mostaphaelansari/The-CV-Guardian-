const PDFAnalyzer = require('../analyzer/pdfAnalyzer');
const fs = require('fs');
const path = require('path');

async function testDetection() {
    const analyzer = new PDFAnalyzer();
    const pdfPath = path.join(__dirname, 'malicious_test.pdf');

    console.log('Reading PDF file...');
    const buffer = fs.readFileSync(pdfPath);

    console.log('Analyzing PDF...');
    const report = await analyzer.analyze(buffer, 'malicious_test.pdf');

    console.log('\n===== ANALYSIS REPORT =====');
    console.log('Score:', report.score);
    console.log('Risk Level:', report.riskLevel);
    console.log('Findings:', report.findings.length);
    console.log('\n===== FINDINGS DETAILS =====');
    report.findings.forEach((finding, i) => {
        console.log(`\n${i + 1}. [${finding.severity.toUpperCase()}] ${finding.check}`);
        console.log(`   ${finding.message}`);
    });
    console.log('\n===== SUMMARY =====');
    console.log(report.summary);
}

testDetection().catch(console.error);
