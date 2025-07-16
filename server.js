const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const authRoutes = require('./routes/auth');
require('dotenv').config();

// Логирование
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

const app = express();
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(cors({
  origin: [
    'https://binary-murex.vercel.app',
    'http://localhost:5173'
  ],
  credentials: true // Для работы с куки
}));

// HTTPS редирект
app.use((req, res, next) => {
  if (req.get('X-Forwarded-Proto') !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(`https://${req.get('host')}${req.url}`);
  }
  next();
});

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Слишком много запросов, попробуйте снова через 15 минут'
});

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', err));

// CSRF защита
const csrfProtection = csurf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } });
app.use(csrfProtection);

// Отправка CSRF-токена клиенту
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Роуты
app.use('/api/auth', authLimiter, authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));