const fs = require('fs');
const http = require('http');

const filePath = process.argv[2] || 'data/malicious_dataset/injected/10001727_injected.txt';
const fileBuffer = fs.readFileSync(filePath);
const fileName = require('path').basename(filePath);

const boundary = '----FormBoundary' + Date.now();
const parts = [
    `--${boundary}\r\n`,
    `Content-Disposition: form-data; name="pdf"; filename="${fileName}"\r\n`,
    `Content-Type: application/octet-stream\r\n\r\n`,
];
const tail = `\r\n--${boundary}--\r\n`;

const body = Buffer.concat([
    Buffer.from(parts.join('')),
    fileBuffer,
    Buffer.from(tail)
]);

const opts = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/analyze',
    method: 'POST',
    headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length
    }
};

const req = http.request(opts, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
        try {
            const j = JSON.parse(data);
            console.log('Score:', j.score);
            console.log('Risk:', j.riskLevel);
            console.log('SafeForLLM:', j.safeForLLM);
            console.log('SanitizationLog:', j.sanitizationLog?.length || 0, 'entries');
            console.log('Findings:', j.findings?.length || 0);
            console.log('ContentIsolation:', !!j.contentIsolationTemplate);
            console.log('SanitizedText present:', !!j.sanitizedText);
        } catch (e) {
            console.error('Response:', data.substring(0, 300));
        }
    });
});

req.on('error', e => console.error('Request error:', e.message));
req.write(body);
req.end();
