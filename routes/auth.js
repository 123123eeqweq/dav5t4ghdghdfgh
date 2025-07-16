const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const router = express.Router();

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
    res.status(201).json({ message: 'Регистрация успешна' });
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
  res.json({ message: 'Вход успешен' });
});

module.exports = router;