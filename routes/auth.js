const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const sgMail = require('@sendgrid/mail');
const { OAuth2Client } = require('google-auth-library');
const { redisClient } = require('../utils/redis');
const User = require('../models/User');
const logger = require('../utils/logger');
const { authenticateToken } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimit');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret-key';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// Настройка SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Настройка Google OAuth
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

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

const verifySchema = Joi.object({
  email: Joi.string().email().required(),
  code: Joi.string().length(6).pattern(/^\d+$/).required()
});

const googleLoginSchema = Joi.object({
  token: Joi.string().required()
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

// Generate random 6-digit code
const generateCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send verification code
const sendVerificationCode = async (email, code) => {
  try {
    const msg = {
      to: email,
      from: process.env.SENDER_EMAIL,
      subject: 'Код подтверждения для Binary Broker',
      text: `Ваш код подтверждения: ${code}`,
      html: `<p>Ваш код подтверждения: <strong>${code}</strong></p>`
    };
    const response = await sgMail.send(msg);
    logger.info(`Verification code sent to ${email}, status: ${response[0].statusCode}`);
    return response;
  } catch (error) {
    logger.error(`Error sending email to ${email}: ${error.message}, response: ${error.response?.body}`);
    throw new Error('Ошибка отправки кода');
  }
};

// Generate tokens
const generateTokens = (email) => {
  const accessToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
  const refreshToken = jwt.sign({ email }, REFRESH_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
};

// Routes
router.post('/register', authLimiter, async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email, password, referralCode } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email уже занят' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword, referralCode, isVerified: false });
    await user.save();

    const code = generateCode();
    await redisClient.set(`verify_code:${email}`, code, { EX: 10 * 60 }); // 10 минут
    await sendVerificationCode(email, code);

    logger.info(`User registered, awaiting verification: ${email}`);
    res.status(201).json({ message: 'Код подтверждения отправлен на email' });
  } catch (error) {
    logger.error(`Registration error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

router.post('/verify', authLimiter, async (req, res) => {
  const { error } = verifySchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email, code } = req.body;
  try {
    const storedCode = await redisClient.get(`verify_code:${email}`);
    if (!storedCode || storedCode !== code) {
      return res.status(400).json({ message: 'Неверный код подтверждения' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Пользователь не найден' });

    user.isVerified = true;
    await user.save();

    const { accessToken, refreshToken } = generateTokens(email);
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 3600000
    });

    await redisClient.del(`verify_code:${email}`);
    logger.info(`User verified: ${email}`);
    res.json({ message: 'Верификация успешна' });
  } catch (error) {
    logger.error(`Verification error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

router.post('/login', authLimiter, async (req, res) => {
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
    if (!user.isVerified) {
      return res.status(403).json({ message: 'Email не подтверждён' });
    }
    const { accessToken, refreshToken } = generateTokens(email);
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 3600000
    });
    await redisClient.del(`login_attempts:${email}`);
    logger.info(`User logged in: ${email}`);
    res.json({ message: 'Вход успешен' });
  } catch (error) {
    logger.error(`Login error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

router.post('/google', authLimiter, async (req, res) => {
  const { error } = googleLoginSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { token } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = payload.email;
    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        email,
        isVerified: true, // Google verifies email
        referralCode: generateCode() // Optional: generate a referral code
      });
      await user.save();
      logger.info(`User registered via Google: ${email}`);
    } else if (!user.isVerified) {
      user.isVerified = true;
      await user.save();
      logger.info(`User verified via Google: ${email}`);
    }

    const { accessToken, refreshToken } = generateTokens(email);
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 3600000
    });

    logger.info(`User logged in via Google: ${email}`);
    res.json({ message: 'Вход через Google успешен' });
  } catch (error) {
    logger.error(`Google login error: ${error.message}`);
    res.status(400).json({ message: 'Ошибка входа через Google' });
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

router.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: 'Refresh-токен отсутствует' });

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(403).json({ message: 'Недействительный refresh-токен' });

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.email);
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000
    });
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 7 * 24 * 3600000
    });
    logger.info(`Token refreshed for ${decoded.email}`);
    res.json({ message: 'Токен обновлён' });
  } catch (error) {
    logger.error(`Refresh token error: ${error.message}`);
    res.status(403).json({ message: 'Недействительный refresh-токен' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/'
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/'
  });
  logger.info('User logged out');
  res.json({ message: 'Выход успешен' });
});

module.exports = router;