const mongoose = require('mongoose');
const config = require('./index');

const connectDB = async () => {
    try {
        const uri = config.MONGO_URI || 'mongodb://localhost:27017/cv-guardian';
        console.log(`Connecting to MongoDB at: ${uri}`);
        const conn = await mongoose.connect(uri);
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

module.exports = connectDB;
