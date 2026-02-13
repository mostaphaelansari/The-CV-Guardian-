const mongoose = require('mongoose');
const config = require('./index');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(config.MONGO_URI || 'mongodb://localhost:27017/cv-guardian', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

module.exports = connectDB;
