const Report = require('../models/Report');
const FileAnalyzer = require('../services/fileAnalyzer');

const analyzer = new FileAnalyzer();

exports.analyzePDF = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const analysisResult = await analyzer.analyze(req.file.buffer, req.file.originalname, req.file.mimetype);

        // Create and save report to MongoDB
        const report = new Report({
            fileName: analysisResult.fileName,
            score: analysisResult.score,
            riskLevel: analysisResult.riskLevel,
            analyzedAt: analysisResult.analyzedAt,
            findings: analysisResult.findings,
            metadata: analysisResult.metadata,
            // fileHash: ... (if we implement hashing later)
        });

        await report.save();

        // Return the report (analysisResult has extra fields like summary/recommendations that aren't in the DB schema explicitly, 
        // but we can return the saved report or merge them. The UI expects the full analysis.)
        // Let's return the saved report object but merged with runtime fields if needed. 
        // For now, returning the mongoose document is fine, but we might lose 'summary' if it's not in the schema.
        // Let's add description/summary to schema if needed, or just return the analysisResult with the ID.

        const response = {
            ...analysisResult,
            id: report._id
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
        const report = await Report.findById(req.params.id);
        if (!report) return res.status(404).json({ error: 'Report not found' });
        res.json(report);
    } catch (error) {
        console.error('Error fetching report:', error);
        res.status(500).json({ error: 'Failed to fetch report' });
    }
};
