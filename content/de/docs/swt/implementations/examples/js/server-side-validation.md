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
    // JWT mit Algorithmus-Whitelist dekodieren und validieren
    const decoded = jwt.verify(token, secret, {
      algorithms: ['HS256', 'HS384', 'HS512'] // Algorithmus-Whitelist
    });

    // Token-Typ als SWT verifizieren
    const header = jwt.decode(token, { complete: true }).header;
    if (header.typ !== 'SWT') {
      throw new Error('Ungültiger Token-Typ - muss SWT sein');
    }

    // Pflicht-Claims prüfen
    if (!decoded.webhook || !decoded.webhook.event || !decoded.iss ||
        !decoded.exp || !decoded.nbf || !decoded.iat || !decoded.jti) {
      throw new Error('Fehlende Pflicht-Claims');
    }

    // Zeitvalidierung mit Uhrzeiten-Toleranz (~60 Sekunden)
    const now = Math.floor(Date.now() / 1000);
    const clockSkew = 60;

    if (decoded.exp <= (now - clockSkew)) {
      throw new Error('Token ist abgelaufen');
    }

    if (decoded.nbf > (now + clockSkew)) {
      throw new Error('Token noch nicht gültig');
    }

    // Hash-Validierung basierend auf Body-Vorhandensein
    const hasBody = payload && Object.keys(payload).length > 0;

    if (hasBody) {
      // Nicht-leerer Body: Hash-Feld ist ERFORDERLICH
      if (!decoded.webhook.hash) {
        throw new Error('Hash-Feld erforderlich für nicht-leeren Body');
      }

      const [algorithm, expectedHash] = decoded.webhook.hash.split(':');
      // Algorithmusname konvertieren (z.B., 'sha-256' zu 'sha256' für Node.js)
      const nodeAlgorithm = algorithm.replace('-', '');
      const actualHash = crypto.createHash(nodeAlgorithm)
                              .update(JSON.stringify(payload))
                              .digest('hex');

      if (actualHash !== expectedHash) {
        throw new Error('Payload-Hash stimmt nicht überein');
      }
    } else {
      // Leerer Body: Hash-Feld MUSS fehlen
      if (decoded.webhook.hash) {
        throw new Error('Hash-Feld muss bei leerem Body fehlen');
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

function createSWT(event, payload, secret, options = {}) {
  const now = Math.floor(Date.now() / 1000);

  const claims = {
    webhook: {
      event: event
    },
    iss: options.issuer || 'webhook-service.example.com',
    exp: now + (options.expiresIn || 300), // Standard: 5 Minuten
    nbf: now,
    iat: now,
    jti: crypto.randomUUID()
  };

  // Optionales Subject hinzufügen
  if (options.subject) {
    claims.sub = options.subject;
  }

  // Optionalen retry_count hinzufügen
  if (options.retryCount !== undefined) {
    claims.webhook.retry_count = options.retryCount;
  }

  // Payload-Hash hinzufügen, wenn Body nicht-leer ist (ERFORDERLICH gemäß Spezifikation)
  if (payload && Object.keys(payload).length > 0) {
    const hash = crypto.createHash('sha256')
                      .update(JSON.stringify(payload))
                      .digest('hex');
    // Standardisierten Algorithmusnamen mit Bindestrich verwenden
    claims.webhook.hash = `sha-256:${hash}`;
  }

  // Mit typ: 'SWT' im Header signieren
  return jwt.sign(claims, secret, {
    algorithm: 'HS256',
    header: { typ: 'SWT' }
  });
}
```