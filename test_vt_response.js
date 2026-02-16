require('dotenv').config();
const virusTotalService = require('./src/services/virusTotalService');
const fs = require('fs');

async function test() {
    console.log(`Checking URL: https://www.google.com`);

    try {
        const result = await virusTotalService.scanUrl('https://www.google.com');
        if (result) {
            fs.writeFileSync('vt_response.json', JSON.stringify(result, null, 2));
            console.log('Response saved to vt_response.json');
        } else {
            console.log('No result returned.');
        }
    } catch (err) {
        console.error('Error:', err.message);
    }
}

test();
