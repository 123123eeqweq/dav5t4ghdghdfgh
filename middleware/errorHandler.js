const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    logger.error(`Invalid CSRF token: ${req.path}, Token: ${req.get('X-CSRF-Token')}, Cookies: ${JSON.stringify(req.cookies)}`);
    return res.status(403).json({ message: 'Неверный CSRF-токен' });
  }
  logger.error(`Server error: ${err.message}`);
  res.status(500).json({ message: 'Ошибка сервера' });
};

module.exports = { errorHandler };