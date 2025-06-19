---
weight: 20
title: "Security Guidelines"
---

# Security Guidelines

## Transport Security

### Use HTTPS
All webhook communication must occur over HTTPS. HTTP connections are not permitted.

### TLS Requirements
- **Minimum requirement**: TLS 1.2+
- **Recommended**: TLS 1.3 for optimal security

## Token Security

### Implement Replay Protection
```javascript
// Example: JTI-based replay protection
const usedTokens = new Set();

function checkReplayProtection(jti) {
  if (usedTokens.has(jti)) {
    throw new Error('Token already used (replay attack)');
  }
  usedTokens.add(jti);
}
```

### Validate Token Timing
```javascript
function validateTokenTiming(decoded) {
  const now = Math.floor(Date.now() / 1000);
  
  if (decoded.exp <= now) {
    throw new Error('Token has expired');
  }
  
  if (decoded.nbf > now) {
    throw new Error('Token is not yet valid');
  }
}
```

### JSON Web Signatures (JWS)
- **Required**: All tokens must be signed
- **Recommended algorithms**: HS256, RS256, ES256

### JSON Web Encryption (JWE)
- **Optional**: Recommended for sensitive data
- **Algorithms**: A256GCM, A256CBC-HS512

## Validation Requirements

### HEAD Requests
```
1. Validate JWT signature
2. Check token expiration  
3. Verify issuer
4. Perform replay protection
```

### POST Requests  
```
1. Validate JWT signature
2. Check token expiration
3. Verify payload hash
4. Validate Content-Length
5. Perform replay protection
```

## Best Practices

### Token Lifetime
- **Short validity period**: Maximum 5-15 minutes
- **Appropriate nbf time**: 1-2 minutes before current time for clock skew

### Replay Protection
- **JTI tracking**: Store already used token IDs
- **TTL-based cleanup**: Automatically remove old JTIs

```javascript
// Example: TTL-based JTI cleanup
class TokenReplayProtection {
  constructor() {
    this.usedTokens = new Map();
  }
  
  addToken(jti, expiration) {
    this.usedTokens.set(jti, expiration);
    this.cleanupExpiredTokens();
  }
  
  cleanupExpiredTokens() {
    const now = Date.now() / 1000;
    for (const [jti, exp] of this.usedTokens.entries()) {
      if (exp < now) {
        this.usedTokens.delete(jti);
      }
    }
  }
}
```

### Monitoring and Logging
- **Log failed validations**
- **Monitor suspicious activities**  
- **Collect token usage statistics**

```javascript
// Example: Security logging
function logSecurityEvent(event, details) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: event,
    details: details,
    severity: event.includes('failed') ? 'HIGH' : 'INFO'
  }));
}
```