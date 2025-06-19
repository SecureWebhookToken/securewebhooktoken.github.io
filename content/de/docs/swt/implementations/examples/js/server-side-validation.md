---
weight: 3
bookCollapseSection: false
title: "Server-seitige Validierung"
---

## Server-seitige Validierung (Node.js)

### Vollständige SWT-Validierung

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function validateSWT(token, payload, secret) {
  try {
    // JWT dekodieren und validieren
    const decoded = jwt.verify(token, secret);
    
    // Pflicht-Claims prüfen
    if (!decoded.webhook || !decoded.iss || !decoded.exp || 
        !decoded.nbf || !decoded.iat || !decoded.jti) {
      throw new Error('Fehlende Pflicht-Claims');
    }
    
    // Zeitvalidierung
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp <= now || decoded.nbf > now) {
      throw new Error('Token abgelaufen oder noch nicht gültig');
    }
    
    // Payload-Hash validieren (falls vorhanden)
    if (payload && decoded.webhook.hash) {
      const [algorithm, expectedHash] = decoded.webhook.hash.split(':');
      const actualHash = crypto.createHash(algorithm)
                              .update(JSON.stringify(payload))
                              .digest('hex');
      
      if (actualHash !== expectedHash) {
        throw new Error('Payload-Hash stimmt nicht überein');
      }
    }
    
    return decoded;
  } catch (error) {
    throw new Error(`SWT-Validierung fehlgeschlagen: ${error.message}`);
  }
}
```

### Token-Erstellung

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
    exp: now + 300, // 5 Minuten gültig
    nbf: now,
    iat: now,
    jti: crypto.randomUUID()
  };
  
  // Payload-Hash hinzufügen (falls vorhanden)
  if (payload) {
    const hash = crypto.createHash('sha256')
                      .update(JSON.stringify(payload))
                      .digest('hex');
    claims.webhook.hash = `sha256:${hash}`;
  }
  
  return jwt.sign(claims, secret, { algorithm: 'HS256' });
}
```