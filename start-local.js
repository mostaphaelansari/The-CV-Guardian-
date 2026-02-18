/**
 * Local Development Runner
 * Starts an in-memory MongoDB instance and launches the main application.
 * Usage: node start-local.js
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const { spawn } = require('child_process');
const path = require('path');

// Colors for console output
const colors = {
    reset: "\x1b[0m",
    bright: "\x1b[1m",
    fgGreen: "\x1b[32m",
    fgYellow: "\x1b[33m",
    fgCyan: "\x1b[36m",
    fgRed: "\x1b[31m"
};

async function start() {
    console.log(`${colors.bright}${colors.fgCyan}🚀 Starting CV Guardian (Local Mode)${colors.reset}\n`);

    // 1. Start In-Memory MongoDB
    console.log(`${colors.fgYellow}➤ Initializing In-Memory Database...${colors.reset}`);
    let mongod;
    try {
        mongod = await MongoMemoryServer.create({
            instance: {
                port: 27017, // Try default port first
                dbName: 'cv-guardian'
            }
        });
    } catch (err) {
        // Fallback to random port if 27017 is taken
        mongod = await MongoMemoryServer.create({
            instance: {
                dbName: 'cv-guardian'
            }
        });
    }

    const uri = mongod.getUri();
    console.log(`${colors.fgGreen}✔ Database started at: ${uri}${colors.reset}\n`);

    // 2. Start Sandbox Service
    console.log(`${colors.fgYellow}➤ Starting Sandbox Service (Port 3001)...${colors.reset}`);
    const sandbox = spawn(/^win/.test(process.platform) ? 'npm.cmd' : 'npm', ['start'], {
        cwd: path.join(__dirname, 'sandbox'),
        stdio: 'inherit',
        shell: true
    });

    // 3. Start Main API
    console.log(`${colors.fgYellow}➤ Starting Main API (Port 3000)...${colors.reset}`);

    // Pass the dynamic Mongo URI to the main process
    const env = { ...process.env, MONGO_URI: uri, PORT: 3000, SANDBOX_URL: 'http://localhost:3001', NLP_SERVICE_URL: 'http://localhost:5000' };

    const server = spawn('node', ['server.js'], {
        cwd: __dirname,
        env: env,
        stdio: 'inherit'
    });

    // Handle shutdown
    const cleanup = async () => {
        console.log(`\n${colors.fgRed}🛑 Shutting down...${colors.reset}`);
        sandbox.kill();
        server.kill();
        if (mongod) await mongod.stop();
        process.exit();
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
}

start().catch(err => {
    console.error(`${colors.fgRed}Fatal Error:${colors.reset}`, err);
    process.exit(1);
});
