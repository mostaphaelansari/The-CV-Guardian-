const fs = require('fs');
const path = require('path');

async function testRawContent() {
    const pdfPath = path.join(__dirname, 'malicious_test.pdf');
    const buffer = fs.readFileSync(pdfPath);

    console.log('Testing raw buffer scanning...\n');

    // Simulate what the analyzer does
    const rawBuffer = buffer.toString('latin1');

    console.log('=== Checking for JavaScript patterns ===');
    const patterns = [
        { pattern: /\/JavaScript/gi, name: '/JavaScript' },
        { pattern: /\/JS\s/gi, name: '/JS ' },
        { pattern: /app\.\w+/gi, name: 'app.something' },
        { pattern: /OpenAction/gi, name: 'OpenAction' }
    ];

    patterns.forEach(({ pattern, name }) => {
        const matches = rawBuffer.match(pattern);
        console.log(`${name}: ${matches ? `Found ${matches.length} match(es)` : 'NOT FOUND'}`);
        if (matches) console.log(`  Matches: ${matches.join(', ')}`);
    });

    console.log('\n=== Raw buffer sample (first 500 chars) ===');
    console.log(rawBuffer.substring(0, 500));
}

testRawContent().catch(console.error);
