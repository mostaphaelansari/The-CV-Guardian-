const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const config = require('../config');
const reportController = require('../controllers/reportController');

// ── Multer Configuration ──
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: config.MAX_FILE_SIZE },
    fileFilter: (_req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (
            file.mimetype === 'application/pdf' ||
            file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
            file.mimetype === 'text/plain' ||
            ext === '.pdf' || ext === '.docx' || ext === '.txt'
        ) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, DOCX, and TXT files are allowed'), false);
        }
    }
});

/**
 * @swagger
 * components:
 *   schemas:
 *     Report:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           description: The auto-generated id of the report
 *         fileName:
 *           type: string
 *           description: The name of the uploaded file
 *         score:
 *           type: number
 *           description: The risk score (0-100)
 *         riskLevel:
 *           type: string
 *           enum: [safe, low, medium, high, critical]
 *           description: The calculated risk level
 *         analyzedAt:
 *           type: string
 *           format: date-time
 *           description: The date the analysis was performed
 *         findings:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               check:
 *                 type: string
 *               severity:
 *                 type: string
 *                 enum: [low, medium, high, critical]
 *               message:
 *                 type: string
 */

/**
 * @swagger
 * /api/analyze:
 *   post:
 *     summary: Upload and analyze a PDF file
 *     tags: [Reports]
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               pdf:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: The analysis report
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Report'
 *       400:
 *         description: Bad request (invalid file type or no file)
 *       413:
 *         description: File too large (max 15MB)
 *       429:
 *         description: Too many requests (rate limit exceeded)
 *       500:
 *         description: Server error
 */
router.post('/analyze', upload.single('pdf'), reportController.analyzePDF);

/**
 * @swagger
 * /api/reports:
 *   get:
 *     summary: Returns the list of past reports
 *     tags: [Reports]
 *     responses:
 *       200:
 *         description: The list of reports
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Report'
 */
router.get('/reports', reportController.getAllReports);

/**
 * @swagger
 * /api/reports/{id}:
 *   get:
 *     summary: Get a report by ID
 *     tags: [Reports]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: The report ID
 *     responses:
 *       200:
 *         description: The report description by id
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Report'
 *       404:
 *         description: Report not found
 */
router.get('/reports/:id', reportController.getReportById);

router.post('/scan-url', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Missing "url" in request body' });
    }

    try {
        const virusTotalService = require('../services/virusTotalService');
        const result = await virusTotalService.scanUrl(url);

        if (!result) {
            // Null result usually means API key missing or error handled internally
            return res.status(503).json({ error: 'Scan service unavailable or API key missing' });
        }

        res.json(result);
    } catch (error) {
        console.error('API Scan Error:', error);
        res.status(500).json({ error: 'Internal server error during scan' });
    }
});

module.exports = router;
