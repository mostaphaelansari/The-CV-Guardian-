require('dotenv').config();
const PDFAnalyzer = require('./analyzer/pdfAnalyzer');
const fs = require('fs');
const path = require('path');

async function analyze() {
    const filePath = path.join(__dirname, 'data', 'CV-selma-koudia-ECC.pdf');
    if (!fs.existsSync(filePath)) {
        console.error('File not found:', filePath);
        return;
    }

    console.log(`Analyzing file: ${filePath}`);
    const buffer = fs.readFileSync(filePath);
    const analyzer = new PDFAnalyzer();

    try {
        const report = await analyzer.analyze(buffer, 'CV-selma-koudia-ECC.pdf');

        console.log('----- ANALYSIS REPORT -----');
        console.log(`Final Score: ${report.score}`);
        console.log(`Risk Level: ${report.riskLevel}`);
        console.log('Page Count:', report.pageCount);
        console.log('Findings:');
        report.findings.forEach(f => {
            console.log(`- [${f.severity.toUpperCase()}] ${f.check}: ${f.message}`);
        });

    } catch (err) {
        console.error('Analysis failed:', err);
    }
}

analyze();
