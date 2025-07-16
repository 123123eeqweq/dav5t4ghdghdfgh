const express = require('express');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const { redisClient } = require('../utils/redis');
const User = require('../models/User');
const logger = require('../utils/logger');
const { authLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// Настройка SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Validation schemas
const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
  token: Joi.string().required(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).required()
});

// Generate reset token
const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Send reset password link
const sendResetPasswordLink = async (email, token) => {
  try {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?email=${encodeURIComponent(email)}&token=${token}`;
    const msg = {
      to: email,
      from: process.env.SENDER_EMAIL,
      subject: 'Сброс пароля для Binary Broker',
      text: `Перейдите по ссылке для сброса пароля: ${resetUrl}\nСсылка действительна 15 минут.`,
      html: `<p>Перейдите по ссылке для сброса пароля: <a href="${resetUrl}">${resetUrl}</a></p><p>Ссылка действительна 15 минут.</p>`
    };
    const response = await sgMail.send(msg);
    logger.info(`Reset password link sent to ${email}, status: ${response[0].statusCode}`);
    return response;
  } catch (error) {
    logger.error(`Error sending reset password email to ${email}: ${error.message}, response: ${error.response?.body}`);
    throw new Error('Ошибка отправки ссылки для сброса пароля');
  }
};

// Routes
router.post('/forgot-password', authLimiter, async (req, res) => {
  const { error } = forgotPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Пользователь не найден' });

    const resetToken = generateResetToken();
    await redisClient.set(`reset_token:${email}`, resetToken, { EX: 15 * 60 }); // 15 минут
    await sendResetPasswordLink(email, resetToken);

    logger.info(`Reset password link generated for ${email}`);
    res.json({ message: 'Ссылка для сброса пароля отправлена на email' });
  } catch (error) {
    logger.error(`Forgot password error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

router.post('/reset-password', authLimiter, async (req, res) => {
  const { error } = resetPasswordSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const { email, token, password } = req.body;
  try {
    const storedToken = await redisClient.get(`reset_token:${email}`);
    if (!storedToken || storedToken !== token) {
      return res.status(400).json({ message: 'Неверный или истёкший токен сброса' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Пользователь не найден' });

    user.password = await bcrypt.hash(password, 12);
    user.isVerified = true; // Reset verified status
    await user.save();

    await redisClient.del(`reset_token:${email}`);
    logger.info(`Password reset for ${email}`);
    res.json({ message: 'Пароль успешно сброшен' });
  } catch (error) {
    logger.error(`Reset password error for ${email}: ${error.message}`);
    res.status(400).json({ message: error.message });
  }
});

module.exports = router;