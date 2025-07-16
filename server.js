const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: [
    'https://binary-murex.vercel.app',
    'http://localhost:5173'
  ],
  credentials: true
}));

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Роуты
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));