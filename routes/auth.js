const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Лучше хранить в .env

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  if (!token) return res.status(401).json({ message: 'Токен отсутствует' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Недействительный токен' });
    req.user = user;
    next();
  });
};

// Регистрация
router.post('/register', async (req, res) => {
  const { email, password, referralCode } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, referralCode });
    await user.save();
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'Регистрация успешна', token });
  } catch (error) {
    res.status(400).json({ message: 'Email уже занят' });
  }
});

// Логин
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email и пароль обязательны' });
  }
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400).json({ message: 'Неверный email или пароль' });
  }
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Вход успешен', token });
});

// Пример защищенного роута
router.get('/profile', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  res.json({ email: user.email, referralCode: user.referralCode });
});

module.exports = router;