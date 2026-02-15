const express = require('express');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.post('/parse', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const buffer = req.file.buffer;
        const mimetype = req.file.mimetype;
        const result = { text: '', pageCount: 0, metadata: {} };

        if (mimetype === 'application/pdf') {
            try {
                const data = await pdfParse(buffer);
                result.text = data.text;
                result.pageCount = data.numpages;
                result.metadata = data.info || {};
            } catch (pdfErr) {
                console.error('PDF parse error (returning partial result):', pdfErr.message);
                result.text = '';
                result.pageCount = 0;
                result.metadata = {};
                result.parseError = pdfErr.message;
            }
        } else if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            try {
                const data = await mammoth.extractRawText({ buffer: buffer });
                result.text = data.value;
                result.pageCount = Math.ceil(result.text.length / 3000) || 1;
            } catch (docxErr) {
                console.error('DOCX parse error (returning partial result):', docxErr.message);
                result.text = '';
                result.pageCount = 0;
                result.parseError = docxErr.message;
            }
        } else if (mimetype === 'text/plain') {
            result.text = buffer.toString('utf-8');
            result.pageCount = Math.ceil(result.text.length / 3000) || 1;
        } else {
            return res.status(400).json({ error: 'Unsupported file type' });
        }

        res.json(result);
    } catch (error) {
        console.error('Parsing error:', error);
        res.status(500).json({ error: 'Failed to parse file: ' + error.message });
    }
});

app.listen(3001, () => {
    console.log('Sandbox service listening on port 3001');
});
