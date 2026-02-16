require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const PDFAnalyzer = require('./analyzer/pdfAnalyzer');

// ── Config ──
const PORT = process.env.PORT || 3000;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Multer – memory storage (no files written to disk) ──
const ALLOWED_MIMES = [
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
];
const ALLOWED_EXTS = ['.pdf', '.docx', '.txt'];

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (_req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ALLOWED_MIMES.includes(file.mimetype) || ALLOWED_EXTS.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, DOCX, and TXT files are allowed'), false);
        }
    }
});

// ── In-memory report store ──
const reports = new Map();
const analyzer = new PDFAnalyzer();

/* ──────────────────────────────────────────────
 * POST /api/analyze  — upload & analyse a PDF
 * ─────────────────────────────────────────────── */
app.post('/api/analyze', upload.single('pdf'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No PDF file uploaded' });
        }

        const report = await analyzer.analyze(req.file.buffer, req.file.originalname);
        report.id = uuidv4();

        // Store (keep last 100 reports)
        reports.set(report.id, report);
        if (reports.size > 100) {
            const oldest = reports.keys().next().value;
            reports.delete(oldest);
        }

        res.json(report);
    } catch (err) {
        if (err.message === 'Only PDF, DOCX, and TXT files are allowed') {
            return res.status(400).json({ error: err.message });
        }
        console.error('Analysis error:', err);
        res.status(500).json({ error: 'Failed to analyse PDF: ' + err.message });
    }
});

/* ──────────────────────────────────────────────
 * GET /api/reports  — list past reports
 * ─────────────────────────────────────────────── */
app.get('/api/reports', (_req, res) => {
    const list = [...reports.values()]
        .map(r => ({
            id: r.id,
            fileName: r.fileName,
            riskLevel: r.riskLevel,
            score: r.score,
            analyzedAt: r.analyzedAt,
            findingsCount: r.findings.length
        }))
        .reverse();   // newest first

    res.json(list);
});

/* ──────────────────────────────────────────────
 * GET /api/reports/:id  — single report
 * ─────────────────────────────────────────────── */
app.get('/api/reports/:id', (req, res) => {
    const report = reports.get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
});

/* ──────────────────────────────────────────────
 * Multer error handler
 * ─────────────────────────────────────────────── */
app.use((err, _req, res, _next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024} MB.` });
        }
        return res.status(400).json({ error: err.message });
    }
    if (err.message === 'Only PDF files are allowed') {
        return res.status(400).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

/* ──────────────────────────────────────────────
 * Start
 * ─────────────────────────────────────────────── */
app.listen(PORT, () => {
    console.log(`\n🛡️  Malicious CV Filter running at http://localhost:${PORT}\n`);
});
