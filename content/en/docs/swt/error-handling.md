---
weight: 30
title: "Error Handling"
---

# Error Handling

## Common Validation Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Token expired` | Token has expired | Request new token |
| `Invalid signature` | Wrong key or manipulated token | Verify key |
| `Hash mismatch` | Payload was modified | Use original payload |
| `Missing claims` | Required claims missing | Correct token structure |
| `Token not yet valid` | nbf-claim is in the future | Check clock synchronization |
| `Replay attack detected` | JTI already used | Generate new token |

## Example Error Handling

```javascript
app.post('/webhook', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const validatedToken = validateSWT(token, req.body, SECRET_KEY);
    
    // Process webhook
    processWebhook(validatedToken.webhook, req.body);
    
    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('Webhook validation failed:', error.message);
    
    // Specific error handling
    if (error.message.includes('expired')) {
      return res.status(401).json({ 
        error: 'TOKEN_EXPIRED',
        message: 'Token has expired'
      });
    }
    
    if (error.message.includes('signature')) {
      return res.status(401).json({ 
        error: 'INVALID_SIGNATURE',
        message: 'Invalid token signature'
      });
    }
    
    if (error.message.includes('Hash')) {
      return res.status(400).json({ 
        error: 'PAYLOAD_MISMATCH',
        message: 'Payload was modified'
      });
    }
    
    // General error
    res.status(401).json({ 
      error: 'UNAUTHORIZED', 
      message: 'Token validation failed'
    });
  }
});
```

## Advanced Error Handling

### Define Error Classes

```javascript
class SWTError extends Error {
  constructor(message, code, statusCode = 401) {
    super(message);
    this.name = 'SWTError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

class TokenExpiredError extends SWTError {
  constructor() {
    super('Token has expired', 'TOKEN_EXPIRED', 401);
  }
}

class InvalidSignatureError extends SWTError {
  constructor() {
    super('Invalid token signature', 'INVALID_SIGNATURE', 401);
  }
}

class PayloadMismatchError extends SWTError {
  constructor() {
    super('Payload hash mismatch', 'PAYLOAD_MISMATCH', 400);
  }
}

class ReplayAttackError extends SWTError {
  constructor() {
    super('Token already used', 'REPLAY_ATTACK', 401);
  }
}
```

### Improved Validation Function

```javascript
function validateSWT(token, payload, secret) {
  try {
    const decoded = jwt.verify(token, secret);
    
    // Check required claims
    const requiredClaims = ['webhook', 'iss', 'exp', 'nbf', 'iat', 'jti'];
    for (const claim of requiredClaims) {
      if (!decoded[claim]) {
        throw new SWTError(`Missing required claim: ${claim}`, 'MISSING_CLAIM', 400);
      }
    }
    
    // Time validation
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp <= now) {
      throw new TokenExpiredError();
    }
    if (decoded.nbf > now) {
      throw new SWTError('Token not yet valid', 'TOKEN_NOT_YET_VALID', 401);
    }
    
    // Validate payload hash
    if (payload && decoded.webhook.hash) {
      const [algorithm, expectedHash] = decoded.webhook.hash.split(':');
      const actualHash = crypto.createHash(algorithm)
                              .update(JSON.stringify(payload))
                              .digest('hex');
      
      if (actualHash !== expectedHash) {
        throw new PayloadMismatchError();
      }
    }
    
    return decoded;
  } catch (error) {
    if (error instanceof SWTError) {
      throw error;
    }
    
    if (error.name === 'TokenExpiredError') {
      throw new TokenExpiredError();
    }
    
    if (error.name === 'JsonWebTokenError') {
      throw new InvalidSignatureError();
    }
    
    throw new SWTError('Unknown validation error', 'VALIDATION_ERROR', 500);
  }
}
```

## Logging and Monitoring

### Structured Logging

```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'webhook-errors.log', level: 'error' }),
    new winston.transports.File({ filename: 'webhook-combined.log' })
  ]
});

function logWebhookEvent(event, details, level = 'info') {
  logger.log({
    level: level,
    message: 'Webhook Event',
    event: event,
    details: details,
    timestamp: new Date().toISOString()
  });
}

// Usage
try {
  const validatedToken = validateSWT(token, req.body, SECRET_KEY);
  logWebhookEvent('webhook_validated', {
    event: validatedToken.webhook.event,
    jti: validatedToken.jti,
    issuer: validatedToken.iss
  });
} catch (error) {
  logWebhookEvent('webhook_validation_failed', {
    error: error.message,
    code: error.code,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  }, 'error');
}
```

### Metrics and Alerting

```javascript
const prometheus = require('prom-client');

// Define metrics
const webhookValidationCounter = new prometheus.Counter({
  name: 'webhook_validation_total',
  help: 'Total number of webhook validations',
  labelNames: ['status', 'error_type']
});

const webhookValidationDuration = new prometheus.Histogram({
  name: 'webhook_validation_duration_seconds',
  help: 'Duration of webhook validation',
  buckets: [0.1, 0.5, 1, 2, 5]
});

// Use metrics
app.post('/webhook', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const validatedToken = validateSWT(token, req.body, SECRET_KEY);
    
    webhookValidationCounter.inc({ status: 'success', error_type: 'none' });
    processWebhook(validatedToken.webhook, req.body);
    
    res.status(200).json({ status: 'success' });
  } catch (error) {
    webhookValidationCounter.inc({ 
      status: 'error', 
      error_type: error.code || 'unknown' 
    });
    
    res.status(error.statusCode || 500).json({
      error: error.code || 'UNKNOWN_ERROR',
      message: error.message
    });
  } finally {
    const duration = (Date.now() - startTime) / 1000;
    webhookValidationDuration.observe(duration);
  }
});
```

## Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const webhookLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Maximum 100 requests per IP
  message: {
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many webhook requests'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Limit authenticated requests less strictly
    const token = req.headers.authorization?.replace('Bearer ', '');
    try {
      jwt.verify(token, SECRET_KEY);
      return false; // Don't skip, but limit less strictly
    } catch {
      return false;
    }
  }
});

app.use('/webhook', webhookLimiter);
```