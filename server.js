const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // Добавляем helmet
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();
app.use(helmet()); // Безопасные заголовки
app.use(express.json());
app.use(cors({
  origin: [
    'https://binary-murex.vercel.app',
    'http://localhost:5173'
  ],
  credentials: true
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Слишком много запросов, попробуйте снова через 15 минут'
});

// HTTPS редирект
app.use((req, res, next) => {
  if (req.get('X-Forwarded-Proto') !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(`https://${req.get('host')}${req.url}`);
  }
  next();
});

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Роуты
app.use('/api/auth', authLimiter, authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));