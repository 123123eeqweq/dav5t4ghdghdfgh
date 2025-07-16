const redis = require('redis');
const logger = require('./logger');

const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
  socket: { tls: true }
});

redisClient.connect().catch(err => logger.error('Redis connection error:', err));

module.exports = { redisClient };