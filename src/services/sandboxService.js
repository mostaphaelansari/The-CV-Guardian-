const axios = require('axios');
const FormData = require('form-data');

const SANDBOX_URL = process.env.SANDBOX_URL || 'http://localhost:3001';
const SANDBOX_TIMEOUT = parseInt(process.env.SANDBOX_TIMEOUT, 10) || 5000; // 5s default

class SandboxService {
    /**
     * Parse a file via the isolated sandbox container.
     * @param {Buffer} fileBuffer - raw file bytes
     * @param {string} originalName - original filename
     * @param {string} mimeType - MIME type
     * @returns {Promise<{text: string, pageCount: number, metadata: object, parseError?: string}>}
     */
    async parseFile(fileBuffer, originalName, mimeType) {
        const form = new FormData();
        form.append('file', fileBuffer, { filename: originalName, contentType: mimeType });

        const response = await axios.post(`${SANDBOX_URL}/parse`, form, {
            headers: { ...form.getHeaders() },
            timeout: SANDBOX_TIMEOUT
        });

        return response.data;
    }

    /**
     * Check if the sandbox service is reachable.
     * @returns {Promise<boolean>}
     */
    async isAvailable() {
        try {
            const response = await axios.get(`${SANDBOX_URL}/health`, {
                timeout: 2000
            });
            return response.status === 200;
        } catch {
            return false;
        }
    }
}

module.exports = new SandboxService();
