const app = require('./src/app');
const config = require('./src/config');

app.listen(config.PORT, () => {
    console.log(`\n🛡️  Malicious CV Filter running at http://localhost:${config.PORT}\n`);
    console.log(`📄 API Documentation available at http://localhost:${config.PORT}/api-docs\n`);
});
