const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { csrfProtection } = require('./middleware/csrf');
const { authLimiter } = require('./middleware/rateLimit');
const { errorHandler } = require('./middleware/errorHandler');
const authRoutes = require('./routes/auth');
const logger = require('./utils/logger');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(cors({
  origin: ['https://binary-murex.vercel.app', 'http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization']
}));

// HTTPS redirect
app.use((req, res, next) => {
  if (req.get('X-Forwarded-Proto') !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(`https://${req.get('host')}${req.url}`);
  }
  next();
});

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', err));

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  try {
    const csrfToken = req.csrfToken();
    logger.info(`CSRF token generated for ${req.ip}`);
    res.json({ csrfToken });
  } catch (err) {
    logger.error(`CSRF token error: ${err.message}`);
    res.status(500).json({ message: 'Ошибка генерации CSRF-токена' });
  }
});

// Routes
app.use('/api/auth', authLimiter, csrfProtection, authRoutes);

// Error handling
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));