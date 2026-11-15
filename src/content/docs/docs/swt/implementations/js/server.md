---
title: "Server-side Validation"
---

## Server-side Validation (Node.js)

### Complete SWT Validation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function validateSWT(token, payload, secret) {
  try {
    // Decode and validate JWT with algorithm allowlist
    const decoded = jwt.verify(token, secret, {
      algorithms: ['HS256', 'HS384', 'HS512'] // Algorithm allowlist
    });

    // Verify token type is SWT
    const header = jwt.decode(token, { complete: true }).header;
    if (header.typ !== 'SWT') {
      throw new Error('Invalid token type - must be SWT');
    }

    // Check required claims
    if (!decoded.webhook || !decoded.webhook.event || !decoded.iss ||
        !decoded.exp || !decoded.nbf || !decoded.iat || !decoded.jti) {
      throw new Error('Missing required claims');
    }

    // Time validation with clock skew tolerance (~60 seconds)
    const now = Math.floor(Date.now() / 1000);
    const clockSkew = 60;

    if (decoded.exp <= (now - clockSkew)) {
      throw new Error('Token has expired');
    }

    if (decoded.nbf > (now + clockSkew)) {
      throw new Error('Token not yet valid');
    }

    // Hash validation based on body presence
    const hasBody = payload && Object.keys(payload).length > 0;

    if (hasBody) {
      // Non-empty body: hash field is REQUIRED
      if (!decoded.webhook.hash) {
        throw new Error('Hash field required for non-empty body');
      }

      const [algorithm, expectedHash] = decoded.webhook.hash.split(':');
      // Convert algorithm name (e.g., 'sha-256' to 'sha256' for Node.js)
      const nodeAlgorithm = algorithm.replace('-', '');
      const actualHash = crypto.createHash(nodeAlgorithm)
                              .update(JSON.stringify(payload))
                              .digest('hex');

      if (actualHash !== expectedHash) {
        throw new Error('Payload hash mismatch');
      }
    } else {
      // Empty body: hash field MUST be absent
      if (decoded.webhook.hash) {
        throw new Error('Hash field must be absent for empty body');
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

function createSWT(event, payload, secret, options = {}) {
  const now = Math.floor(Date.now() / 1000);

  const claims = {
    webhook: {
      event: event
    },
    iss: options.issuer || 'webhook-service.example.com',
    exp: now + (options.expiresIn || 300), // Default: 5 minutes
    nbf: now,
    iat: now,
    jti: crypto.randomUUID()
  };

  // Add optional subject
  if (options.subject) {
    claims.sub = options.subject;
  }

  // Add optional retry_count
  if (options.retryCount !== undefined) {
    claims.webhook.retry_count = options.retryCount;
  }

  // Add payload hash if body is non-empty (REQUIRED by spec)
  if (payload && Object.keys(payload).length > 0) {
    const hash = crypto.createHash('sha256')
                      .update(JSON.stringify(payload))
                      .digest('hex');
    // Use standardized algorithm name with hyphen
    claims.webhook.hash = `sha-256:${hash}`;
  }

  // Sign with typ: 'SWT' in header
  return jwt.sign(claims, secret, {
    algorithm: 'HS256',
    header: { typ: 'SWT' }
  });
}
```