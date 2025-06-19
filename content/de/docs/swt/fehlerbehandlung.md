---
weight: 30
title: "Fehlerbehandlung"
---

# Fehlerbehandlung

## Häufige Validierungsfehler

| Fehler | Ursache | Lösung |
|--------|---------|--------|
| `Token expired` | Token ist abgelaufen | Neues Token anfordern |
| `Invalid signature` | Falscher Schlüssel oder manipuliertes Token | Schlüssel überprüfen |
| `Hash mismatch` | Payload wurde verändert | Originale Payload verwenden |
| `Missing claims` | Pflicht-Claims fehlen | Token-Struktur korrigieren |
| `Token not yet valid` | nbf-Claim liegt in der Zukunft | Clock-Synchronisation prüfen |
| `Replay attack detected` | JTI bereits verwendet | Neues Token generieren |

## Beispiel-Fehlerbehandlung

```javascript
app.post('/webhook', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const validatedToken = validateSWT(token, req.body, SECRET_KEY);
    
    // Webhook verarbeiten
    processWebhook(validatedToken.webhook, req.body);
    
    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('Webhook-Validierung fehlgeschlagen:', error.message);
    
    // Spezifische Fehlerbehandlung
    if (error.message.includes('expired')) {
      return res.status(401).json({ 
        error: 'TOKEN_EXPIRED',
        message: 'Token ist abgelaufen'
      });
    }
    
    if (error.message.includes('signature')) {
      return res.status(401).json({ 
        error: 'INVALID_SIGNATURE',
        message: 'Token-Signatur ungültig'
      });
    }
    
    if (error.message.includes('Hash')) {
      return res.status(400).json({ 
        error: 'PAYLOAD_MISMATCH',
        message: 'Payload wurde verändert'
      });
    }
    
    // Allgemeiner Fehler
    res.status(401).json({ 
      error: 'UNAUTHORIZED', 
      message: 'Token-Validierung fehlgeschlagen'
    });
  }
});
```

## Erweiterte Fehlerbehandlung

### Fehlerklassen definieren

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
    super('Token ist abgelaufen', 'TOKEN_EXPIRED', 401);
  }
}

class InvalidSignatureError extends SWTError {
  constructor() {
    super('Token-Signatur ungültig', 'INVALID_SIGNATURE', 401);
  }
}

class PayloadMismatchError extends SWTError {
  constructor() {
    super('Payload-Hash stimmt nicht überein', 'PAYLOAD_MISMATCH', 400);
  }
}

class ReplayAttackError extends SWTError {
  constructor() {
    super('Token bereits verwendet', 'REPLAY_ATTACK', 401);
  }
}
```

### Verbesserte Validierungsfunktion

```javascript
function validateSWT(token, payload, secret) {
  try {
    const decoded = jwt.verify(token, secret);
    
    // Pflicht-Claims prüfen
    const requiredClaims = ['webhook', 'iss', 'exp', 'nbf', 'iat', 'jti'];
    for (const claim of requiredClaims) {
      if (!decoded[claim]) {
        throw new SWTError(`Fehlender Pflicht-Claim: ${claim}`, 'MISSING_CLAIM', 400);
      }
    }
    
    // Zeitvalidierung
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp <= now) {
      throw new TokenExpiredError();
    }
    if (decoded.nbf > now) {
      throw new SWTError('Token noch nicht gültig', 'TOKEN_NOT_YET_VALID', 401);
    }
    
    // Payload-Hash validieren
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
    
    throw new SWTError('Unbekannter Validierungsfehler', 'VALIDATION_ERROR', 500);
  }
}
```

## Logging und Monitoring

### Strukturiertes Logging

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

// Verwendung
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

### Metriken und Alerting

```javascript
const prometheus = require('prom-client');

// Metriken definieren
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

// Metriken verwenden
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
  windowMs: 15 * 60 * 1000, // 15 Minuten
  max: 100, // Maximal 100 Requests pro IP
  message: {
    error: 'RATE_LIMIT_EXCEEDED',
    message: 'Zu viele Webhook-Anfragen'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Authentifizierte Requests weniger limitieren
    const token = req.headers.authorization?.replace('Bearer ', '');
    try {
      jwt.verify(token, SECRET_KEY);
      return false; // Nicht skippen, aber weniger streng limitieren
    } catch {
      return false;
    }
  }
});

app.use('/webhook', webhookLimiter);
```