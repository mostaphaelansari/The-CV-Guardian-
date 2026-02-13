const axios = require('axios');
const FormData = require('form-data');

const SANDBOX_URL = process.env.SANDBOX_URL || 'http://localhost:3001';

class SandboxService {
    async parseFile(fileBuffer, originalName, mimeType) {
        try {
            const form = new FormData();
            form.append('file', fileBuffer, { filename: originalName, contentType: mimeType });

            const response = await axios.post(`${SANDBOX_URL}/parse`, form, {
                headers: {
                    ...form.getHeaders()
                }
            });

            return response.data;
        } catch (error) {
            console.error('Sandbox Service Error:', error.message);
            // Fallback? Or throw to handle in analyzer?
            // If sandbox is down, we might want to fail secure (deny)
            throw new Error('Sandbox service unavailable: ' + error.message);
        }
    }
}

module.exports = new SandboxService();
