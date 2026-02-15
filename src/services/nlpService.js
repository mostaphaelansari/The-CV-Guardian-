const axios = require('axios');

const NLP_SERVICE_URL = process.env.NLP_SERVICE_URL || 'http://localhost:5000';

class NLPService {
    async analyzeText(text) {
        try {
            const response = await axios.post(`${NLP_SERVICE_URL}/analyze`, { text });
            return response.data;
        } catch (error) {
            console.error('NLP Service Error:', error.message);
            return null; // Fail silently or return default
        }
    }
}

module.exports = new NLPService();
