const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const { Document, Packer, Paragraph, TextRun } = require('docx');

async function createDocx() {
    const doc = new Document({
        sections: [{
            properties: {},
            children: [
                new Paragraph({
                    children: [
                        new TextRun("Hello World! This is a test CV."),
                        new TextRun({
                            text: "Suspicious keyword: password is",
                            bold: true,
                        }),
                    ],
                }),
            ],
        }],
    });

    return await Packer.toBuffer(doc);
}

async function runTest() {
    console.log('Generating DOCX...');
    const buffer = await createDocx();
    console.log(`Generated DOCX size: ${buffer.length} bytes`);

    const form = new FormData();
    form.append('pdf', buffer, { filename: 'test_cv.docx', contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });

    try {
        console.log('Uploading DOCX...');
        const res = await axios.post('http://localhost:3000/api/analyze', form, {
            headers: form.getHeaders()
        });
        console.log('Success! Status:', res.status);
        console.log('Report:', JSON.stringify(res.data, null, 2));
    } catch (err) {
        console.error('Upload failed!');
        if (err.response) {
            console.error('Status:', err.response.status);
            console.error('Data:', err.response.data);
        } else {
            console.error('Error:', err.message);
        }
    }
}

runTest();
