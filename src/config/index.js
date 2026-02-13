const path = require('path');

const config = {
    PORT: process.env.PORT || 3000,
    MAX_FILE_SIZE: 15 * 1024 * 1024, // 15 MB
    UPLOAD_DIR: path.join(__dirname, '../../public/uploads') // if needed, though we use memory storage
};

module.exports = config;
