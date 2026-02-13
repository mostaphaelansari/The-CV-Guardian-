const { v4: uuidv4 } = require('uuid');
const FileAnalyzer = require('../services/fileAnalyzer');

// In-memory report store
const reports = new Map();
const analyzer = new FileAnalyzer();

exports.analyzePDF = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const report = await analyzer.analyze(req.file.buffer, req.file.originalname, req.file.mimetype);
        report.id = uuidv4();

        // Store (keep last 100 reports)
        reports.set(report.id, report);
        if (reports.size > 100) {
            const oldest = reports.keys().next().value;
            reports.delete(oldest);
        }

        res.json(report);
    } catch (err) {
        if (err.message.includes('Only PDF, DOCX, and TXT files are allowed')) {
            return res.status(400).json({ error: err.message });
        }
        console.error('Analysis error:', err);
        res.status(500).json({ error: 'Failed to analyze file: ' + err.message });
    }
};

exports.getAllReports = (req, res) => {
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
};

exports.getReportById = (req, res) => {
    const report = reports.get(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
};
