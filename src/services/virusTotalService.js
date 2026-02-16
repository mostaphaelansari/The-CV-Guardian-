const axios = require('axios');
const config = require('../config');

class VirusTotalService {
    constructor() {
        this.apiKey = config.VIRUSTOTAL_API_KEY;
        this.baseUrl = 'https://www.virustotal.com/api/v3';
        this.cache = new Map(); // Simple in-memory cache to avoid rate limits
    }

    /**
     * Scan a URL using VirusTotal API
     * @param {string} url - The URL to scan
     * @returns {Promise<object>} - Scan result { malicious: boolean, suspicious: boolean, analysis: object }
     */
    async scanUrl(url) {
        if (!this.apiKey || this.apiKey === 'your_api_key_here') {
            console.warn('VirusTotal API key is missing or not configured.');
            return null; // Skip if no key
        }

        // Check cache first
        if (this.cache.has(url)) {
            return this.cache.get(url);
        }

        try {
            // 1. Submit URL for scanning
            const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '');

            // First, try to get an existing analysis report
            try {
                const reportUrl = `${this.baseUrl}/urls/${encodedUrl}`;
                const response = await axios.get(reportUrl, {
                    headers: { 'x-apikey': this.apiKey }
                });

                const stats = response.data.data.attributes.last_analysis_stats;
                const result = {
                    malicious: stats.malicious > 0,
                    suspicious: stats.suspicious > 0,
                    harmless: stats.harmless > 0,
                    stats: stats,
                    scanDate: response.data.data.attributes.last_analysis_date
                };

                this.cache.set(url, result);
                return result;

            } catch (err) {
                if (err.response && err.response.status === 404) {
                    // URL not found, need to submit it first (omitted for now to avoid quota burn/complexity of async polling)
                    // For a real-time CV scanner, we mostly care about *known* malicious URLs.
                    console.log(`URL not found in VirusTotal database: ${url}`);
                    return { malicious: false, suspicious: false, comments: 'Not in database' };
                }
                throw err;
            }

        } catch (error) {
            console.error(`VirusTotal scan failed for ${url}:`, error.message);
            if (error.response && error.response.status === 429) {
                console.warn('VirusTotal rate limit exceeded.');
            }
            return null; // Fail safe
        }
    }
}

module.exports = new VirusTotalService();
