---
weight: 2
bookCollapseSection: false
title: "Replay Protection with Redis"
---

# Replay Protection with Redis

```javascript
const redis = require('redis');
const client = redis.createClient();

class RedisReplayProtection {
  constructor(redisClient) {
    this.redis = redisClient;
  }
  
  async checkAndAddToken(jti, expiration) {
    const exists = await this.redis.exists(`swt:${jti}`);
    if (exists) {
      throw new Error('Token already used (replay attack)');
    }
    
    const ttl = expiration - Math.floor(Date.now() / 1000);
    if (ttl > 0) {
      await this.redis.setex(`swt:${jti}`, ttl, '1');
    }
  }
}

// Usage
const replayProtection = new RedisReplayProtection(client);

async function validateSWTWithReplayProtection(token, payload, secret) {
  const decoded = validateSWT(token, payload, secret);
  await replayProtection.checkAndAddToken(decoded.jti, decoded.exp);
  return decoded;
}
```