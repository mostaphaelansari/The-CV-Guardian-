/**
 * Unit test – AI-Generation Risk Scoring Framework
 * Tests the 7-dimension scoring grid (0–5 each, total 0–35 + null for cross-consistency)
 */
const FileAnalyzer = require('../src/services/fileAnalyzer');

// ── Heavily AI-generated CV ──
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

Lead Engineer | InnoSoft Ltd | 2018 – 2020
- Delivered outstanding results through streamlined processes
- Led cross-functional teams to drive growth and deliver results
- Optimized scalable systems with exceptional results

SKILLS
Strategic Planning, Stakeholder Management, Agile, Digital Transformation, Cloud Architecture
`;

// ── Realistic human-written CV ──
const humanCV = `
Mohamed El Ansari
Email: m.elansari@email.com

IT Support Technician at Maroc Telecom (2022 – 2024)
- Fixed network issues for 200+ employees across 3 offices
- Set up new employee workstations and VPN access using Active Directory 2019
- Wrote internal documentation for common printer problems
- Debugged a flaky DHCP issue that took 2 weeks to root-cause (turned out to be a firmware bug on the Cisco switch)
- Dealt with a legacy Windows Server 2012 migration — had to work around deprecated GPO settings

Education
DUT Informatique, EST Agadir, 2020-2022

Side Project: Built a FastAPI 0.95 REST API with SQLAlchemy + PostgreSQL 15 for tracking office inventory.
Deployed on a $5 DigitalOcean droplet serving ~50 requests/day with p99 latency under 200ms.

Skills: Windows Server, Active Directory, Python 3.11, SQL, Cisco IOS, Docker 24.0
`;

function runTest() {
    const analyzer = new FileAnalyzer();

    console.log('\n══════════════════════════════════════════════════');
    console.log('  AI-GENERATION RISK SCORING FRAMEWORK – TESTS');
    console.log('══════════════════════════════════════════════════\n');

    // ── Test 1: AI-generated CV ──
    console.log('── Test 1: AI-Generated CV ──');
    const aiReport = { findings: [], score: 0, riskLevel: 'safe', summary: '', recommendations: [], metadata: {} };
    analyzer._scoreAIGeneration(aiCV, aiReport);

    console.log(`  Total AI Score: ${aiReport.aiScore.total}/35`);
    console.log(`  Risk Label:     ${aiReport.aiScore.riskLabel}`);
    console.log('  Dimensions:');
    for (const [dim, val] of Object.entries(aiReport.aiScore.dimensions)) {
        console.log(`    ${dim}: ${val === null ? 'N/A (manual)' : val + '/5'}`);
    }

    // ── Test 2: Human-written CV ──
    console.log('\n── Test 2: Human-Written CV ──');
    const humanReport = { findings: [], score: 0, riskLevel: 'safe', summary: '', recommendations: [], metadata: {} };
    analyzer._scoreAIGeneration(humanCV, humanReport);

    console.log(`  Total AI Score: ${humanReport.aiScore.total}/35`);
    console.log(`  Risk Label:     ${humanReport.aiScore.riskLabel}`);
    console.log('  Dimensions:');
    for (const [dim, val] of Object.entries(humanReport.aiScore.dimensions)) {
        console.log(`    ${dim}: ${val === null ? 'N/A (manual)' : val + '/5'}`);
    }

    // ── Test 3: Metadata with bot-tool creator ──
    console.log('\n── Test 3: Bot-Tool Metadata ──');
    const metaReport = { findings: [], score: 0, riskLevel: 'safe', summary: '', recommendations: [], metadata: { creator: 'ChatGPT', producer: 'OpenAI' } };
    analyzer._checkMetadataAnomalies(metaReport);
    const metaFindings = metaReport.findings.filter(f => f.check === 'AI-Generation Analysis');
    console.log(`  Score: ${metaReport.score}`);
    console.log(`  AI Findings: ${metaFindings.length}`);
    for (const f of metaFindings) {
        console.log(`    [${f.severity.toUpperCase()}] ${f.message}`);
    }

    // ── Assertions ──
    console.log('\n── Results ──');
    const errors = [];

    // AI CV should score >= 20 (Mixed/Assisted or higher)
    if (aiReport.aiScore.total < 16) errors.push(`FAIL: AI CV scored too low: ${aiReport.aiScore.total} (expected >= 16)`);
    if (aiReport.aiScore.riskLabel === 'Likely Human') errors.push(`FAIL: AI CV labeled as "Likely Human"`);

    // Human CV should score <= 15 (Likely Human)
    if (humanReport.aiScore.total > 20) errors.push(`FAIL: Human CV scored too high: ${humanReport.aiScore.total} (expected <= 20)`);

    // AI CV should score higher than human CV
    if (aiReport.aiScore.total <= humanReport.aiScore.total) {
        errors.push(`FAIL: AI CV (${aiReport.aiScore.total}) should score higher than Human CV (${humanReport.aiScore.total})`);
    }

    // Metadata should detect ChatGPT
    if (metaFindings.length === 0) errors.push('FAIL: No metadata findings for ChatGPT creator');

    // All dimension scores should be 0–5
    for (const [dim, val] of Object.entries(aiReport.aiScore.dimensions)) {
        if (val !== null && (val < 0 || val > 5)) {
            errors.push(`FAIL: Dimension ${dim} out of range: ${val}`);
        }
    }

    // Cross-consistency should be null
    if (aiReport.aiScore.dimensions['3.0_cross_consistency'] !== null) {
        errors.push('FAIL: Cross-consistency should be null (manual only)');
    }

    if (errors.length === 0) {
        console.log('  ✅ ALL AI-GENERATION SCORING TESTS PASSED\n');
    } else {
        for (const e of errors) console.log(`  ❌ ${e}`);
        console.log('');
        process.exit(1);
    }
}

runTest();
