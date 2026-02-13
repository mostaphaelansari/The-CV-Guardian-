const fs = require('fs');
const path = require('path');
// Mock modules
const mockAxios = {
    post: async (url, data) => {
        if (url.includes('analyze')) { // NLP
            console.log('Mock NLP Service called');
            return { data: [{ label: 'NEGATIVE', score: 0.95 }] };
        }
        if (url.includes('parse')) { // Sandbox
            console.log('Mock Sandbox Service called');
            return {
                data: {
                    text: "This is a test CV content with some negative sentiment. malicious code here.",
                    pageCount: 1,
                    metadata: { Creator: "Test Creator" }
                }
            };
        }
        return { data: {} };
    }
};

const mockMongoose = {
    connect: async () => console.log('Mock Mongoose connected'),
    model: (name, schema) => {
        return class MockModel {
            constructor(data) { this.data = data; }
            async save() {
                console.log(`Mock ${name} saved:`, this.data.fileName);
                this._id = 'mock-id';
                return this;
            }
            static async find() { return { sort: () => { return { limit: () => [] } } } }
        };
    },
    Schema: class { },
};

// Override requires for testing
const requireOriginal = require;
require = (moduleName) => {
    if (moduleName === 'axios') return mockAxios;
    if (moduleName === 'mongoose') return mockMongoose;
    return requireOriginal(moduleName);
};

// Start logic
async function runVerification() {
    try {
        console.log("Starting Verification...");

        const rootDir = path.join(__dirname, '..');
        console.log("Checking file existence in:", rootDir);

        if (!fs.existsSync(path.join(rootDir, 'src/config/db.js'))) throw new Error("db.js missing");
        if (!fs.existsSync(path.join(rootDir, 'src/models/Report.js'))) throw new Error("Report.js missing");
        if (!fs.existsSync(path.join(rootDir, 'sandbox/server.js'))) throw new Error("Sandbox server.js missing");
        if (!fs.existsSync(path.join(rootDir, 'nlp_service/app.py'))) throw new Error("NLP app.py missing");

        console.log("All components present.");

        // Syntax check
        const analyzerCode = fs.readFileSync(path.join(rootDir, 'src/services/fileAnalyzer.js'), 'utf8');
        if (!analyzerCode.includes('sandboxService')) throw new Error("FileAnalyzer does not use sandboxService");
        if (!analyzerCode.includes('nlpService')) throw new Error("FileAnalyzer does not use nlpService");

        console.log("Integration checks passed.");

    } catch (e) {
        console.error("Verification Failed:", e.message);
        process.exit(1);
    }
}

runVerification();
