const fs = require('fs');
const pdfParse = require('pdf-parse');

async function test() {
    try {
        // Create a dummy PDF buffer or load one if available
        // A valid minimal PDF (1.4)
        const pdfBuffer = Buffer.from(
            '%PDF-1.4\n' +
            '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
            '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' +
            '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>\nendobj\n' +
            'xref\n' +
            '0 4\n' +
            '0000000000 65535 f \n' +
            '0000000010 00000 n \n' +
            '0000000060 00000 n \n' +
            '0000000117 00000 n \n' +
            'trailer\n<< /Size 4 /Root 1 0 R >>\n' +
            'startxref\n223\n%%EOF'
        );

        console.log('Parsing PDF...');
        const data = await pdfParse(pdfBuffer);
        console.log('Success:', data.info);
    } catch (err) {
        console.error('Caught Error:', err.message);
    }
}

test();
