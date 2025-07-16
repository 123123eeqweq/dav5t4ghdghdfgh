const redis = require('redis');

const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
  socket: { tls: true }
});

redisClient.connect().catch(err => console.error('Redis connection error:', err));

module.exports = { redisClient };