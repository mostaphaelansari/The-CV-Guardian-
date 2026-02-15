const PDFAnalyzer = require('../../analyzer/pdfAnalyzer');
let Report;
try { Report = require('../models/Report'); } catch { Report = null; }

const analyzer = new PDFAnalyzer();

exports.analyzePDF = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const analysisResult = await analyzer.analyze(req.file.buffer, req.file.originalname);

        // Try to persist to MongoDB (optional — works without DB)
        let savedId = null;
        if (Report) {
            try {
                const report = new Report({
                    fileName: analysisResult.fileName,
                    score: analysisResult.score,
                    riskLevel: analysisResult.riskLevel,
                    analyzedAt: analysisResult.analyzedAt,
                    findings: analysisResult.findings,
                    metadata: analysisResult.metadata,
                });
                await report.save();
                savedId = report._id;
            } catch { /* DB unavailable – continue without persistence */ }
        }

        const response = {
            ...analysisResult,
            ...(savedId ? { id: savedId } : {})
        };

        res.json(response);
    } catch (err) {
        if (err.message && err.message.includes('Only PDF, DOCX, and TXT files are allowed')) {
            return res.status(400).json({ error: err.message });
        }
        console.error('Analysis error:', err);
        res.status(500).json({ error: 'Failed to analyze file: ' + err.message });
    }
};

exports.getAllReports = async (req, res) => {
    try {
        if (!Report) return res.json([]);
        const reports = await Report.find().sort({ analyzedAt: -1 }).limit(100);

        const list = reports.map(r => ({
            id: r._id,
            fileName: r.fileName,
            riskLevel: r.riskLevel,
            score: r.score,
            analyzedAt: r.analyzedAt,
            findingsCount: r.findings.length
        }));

        res.json(list);
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
};

exports.getReportById = async (req, res) => {
    try {
        if (!Report) return res.status(404).json({ error: 'Report not found' });
        const report = await Report.findById(req.params.id);
        if (!report) return res.status(404).json({ error: 'Report not found' });
        res.json(report);
    } catch (error) {
        console.error('Error fetching report:', error);
        res.status(500).json({ error: 'Failed to fetch report' });
    }
};
