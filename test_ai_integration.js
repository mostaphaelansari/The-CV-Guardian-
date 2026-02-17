const PDFAnalyzer = require('./analyzer/pdfAnalyzer');

// ── Heavily AI-generated CV Text ──
const aiCV = `
JANE SMITH
Email: jane.smith@example.com | LinkedIn: linkedin.com/in/janesmith

PROFESSIONAL SUMMARY
Results-driven professional with a proven track record of delivering high-impact solutions.
Highly motivated and dedicated team player with strong interpersonal and communication skills.
Passionate about leveraging cutting-edge technologies to drive business growth.
Adept at collaborating with cross-functional teams to streamline operations and optimize performance.
Detail-oriented professional with a keen eye for detail and committed to continuous improvement.
Seeking to leverage my expertise in a dynamic and fast-paced environment.

EXPERIENCE
Senior Project Manager | TechCorp Inc. | 2020 – Present
- Spearheaded the implementation of scalable cloud infrastructure
- Leveraged best-in-class methodologies to optimize workflow efficiently
- Orchestrated cross-functional synergy across multiple stakeholder groups seamlessly
- Streamlined operations resulting in robust value-add to the ecosystem effectively
- Spearheaded innovative disruption strategies for holistic paradigm shifts successfully
- Managed world-class teams to deliver cutting-edge solutions flawlessly

SKILLS
Strategic Planning, Stakeholder Management, Agile, Digital Transformation, Cloud Architecture
`;

async function runTest() {
    const analyzer = new PDFAnalyzer();
    const report = {
        findings: [],
        score: 0,
        riskLevel: 'safe',
        summary: '',
        recommendations: [],
        metadata: {}
    };

    console.log('Testing AI Scoring Integration in PDFAnalyzer...');

    // Call the internal method directly or simulate the full analyze flow
    // Since _scoreAIGeneration is internal, we'll verify it by calling it directly 
    // to confirm presence, or verify via full analyze if we had a buffer.
    // For now, let's verify the method exists and runs.

    if (typeof analyzer._scoreAIGeneration !== 'function') {
        console.error('❌ FAIL: _scoreAIGeneration method not found on PDFAnalyzer instance!');
        process.exit(1);
    }

    analyzer._scoreAIGeneration(aiCV, report);

    console.log(`AI Score: ${report.aiScore.total}/35`);
    console.log(`Risk Label: ${report.aiScore.riskLabel}`);

    if (report.aiScore.total > 25) {
        console.log('✅ PASS: AI CV correctly scored as high risk.');
    } else {
        console.error('❌ FAIL: AI CV scored too low.');
    }
}

runTest();
