const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { redisClient } = require('../utils/redis');
const User = require('../models/User');
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Validation schemas
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).required(),
  referralCode: Joi.string().length(6).alphanum().allow('').optional()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// Brute force protection
const checkLoginAttempts = async (email) => {
  const key = `login_attempts:${email}`;
  const attempts = await redisClient.get(key);
  const maxAttempts = 5;
  const lockoutTime = 15 * 60;

  if (attempts && parseInt(attempts) >= maxAttempts) {
    const ttl = await redisClient.ttl(key);
    throw new Error(`Слишком много попыток. Попробуйте снова через ${Math.ceil(ttl / 60)} минут`);
  }
};

// Routes
router.post('/register', async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email, password, referralCode } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword, referralCode });
    await user.save();
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    logger.info(`User registered: ${email}`);
    res.status(201).json({ message: 'Регистрация успешна' });
  } catch (error) {
    logger.error(`Registration error for ${email}: ${error.message}`);
    res.status(400).json({ message: 'Email уже занят' });
  }
});

router.post('/login', async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email, password } = req.body;
  try {
    await checkLoginAttempts(email);
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      const key = `login_attempts:${email}`;
      const attempts = await redisClient.incr(key);
      if (attempts === 1) await redisClient.expire(key, 15 * 60);
      logger.warn(`Failed login attempt for ${email}: ${attempts}/${5}`);
      return res.status(400).json({ message: `Неверный email или пароль. Попыток осталось: ${5 - attempts}` });
    }
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    await redisClient.del(`login_attempts:${email}`);
    logger.info(`User logged in: ${email}`);
    res.json({ message: 'Вход успешен' });
  } catch (error) {
    logger.error(`Login error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    res.json({ email: user.email, referralCode: user.referralCode });
  } catch (error) {
    logger.error(`Profile error for ${req.user.email}: ${error.message}`);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token');
  logger.info('User logged out');
  res.json({ message: 'Выход успешен' });
});

module.exports = router;