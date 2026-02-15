const fs = require('fs');
const PDFAnalyzer = require('../analyzer/pdfAnalyzer');

(async () => {
    const analyzer = new PDFAnalyzer();
    const buf = fs.readFileSync('C:/Users/mosta/Downloads/Mostapha_EL_ANSARI_CV_Data_Science.pdf');
    const report = await analyzer.analyze(buf, 'Mostapha_EL_ANSARI_CV_Data_Science.pdf');

    console.log('\n=== LATEX CV TEST ===');
    console.log('Score:', report.score);
    console.log('Risk:', report.riskLevel);
    console.log('safeForLLM:', report.safeForLLM);
    console.log('Findings:', report.findings.length);
    console.log('');

    for (const f of report.findings) {
        console.log(`  [${f.severity.toUpperCase()}] ${f.check}`);
        console.log(`    ${f.message.substring(0, 160)}`);
        console.log('');
    }
})();
