---
weight: 3
bookCollapseSection: false
title: "Server-side Validation"
---

## Server-side Validation (Node.js)

### Complete SWT Validation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function validateSWT(token, payload, secret) {
  try {
    // Decode and validate JWT
    const decoded = jwt.verify(token, secret);
    
    // Check required claims
    if (!decoded.webhook || !decoded.iss || !decoded.exp || 
        !decoded.nbf || !decoded.iat || !decoded.jti) {
      throw new Error('Missing required claims');
    }
    
    // Time validation
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp <= now || decoded.nbf > now) {
      throw new Error('Token expired or not yet valid');
    }
    
    // Validate payload hash (if present)
    if (payload && decoded.webhook.hash) {
      const [algorithm, expectedHash] = decoded.webhook.hash.split(':');
      const actualHash = crypto.createHash(algorithm)
                              .update(JSON.stringify(payload))
                              .digest('hex');
      
      if (actualHash !== expectedHash) {
        throw new Error('Payload hash mismatch');
      }
    }
    
    return decoded;
  } catch (error) {
    throw new Error(`SWT validation failed: ${error.message}`);
  }
}
```

### Token Creation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function createSWT(webhookData, payload, secret) {
  const now = Math.floor(Date.now() / 1000);
  
  const claims = {
    webhook: {
      event: webhookData.event,
      data: webhookData.data
    },
    iss: 'webhook-service.example.com',
    exp: now + 300, // Valid for 5 minutes
    nbf: now,
    iat: now,
    jti: crypto.randomUUID()
  };
  
  // Add payload hash (if present)
  if (payload) {
    const hash = crypto.createHash('sha256')
                      .update(JSON.stringify(payload))
                      .digest('hex');
    claims.webhook.hash = `sha256:${hash}`;
  }
  
  return jwt.sign(claims, secret, { algorithm: 'HS256' });
}
```