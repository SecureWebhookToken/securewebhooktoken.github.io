---
title: "SWT Security Guidelines & Best Practices"
description: "Security guidelines for Secure Webhook Tokens: TLS requirements, algorithm allowlisting, JTI replay protection, clock skew leeway, and logging."
---

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
function validateTokenTiming(decoded, clockSkew = 60) {
  const now = Math.floor(Date.now() / 1000);

  // Apply clock skew tolerance
  if (decoded.exp <= (now - clockSkew)) {
    throw new Error('Token has expired');
  }

  if (decoded.nbf > (now + clockSkew)) {
    throw new Error('Token is not yet valid');
  }
}
```

### Signature Algorithms
- **Required**: All tokens must be signed
- **Algorithm allowlist**: Implementations MUST maintain an allowlist of approved algorithms
- **Reject "none"**: Always reject tokens with algorithm "none"
- **Recommended algorithms**: HS256, HS384, HS512 (HMAC variants) for balance of security and performance
- **Alternative algorithms**: RS256, ES256 may be used when asymmetric cryptography is required

## Validation Requirements

All SWT tokens must be transmitted via HTTP POST. The validation workflow is:

```
1. Verify JWT signature and structure
2. Verify token type is SWT (typ: "SWT")
3. Validate standard claims (exp, nbf, iat, iss, jti)
4. Verify algorithm is on allowlist (reject "none")
5. Confirm webhook claim exists with event field
6. For non-empty request bodies:
   - Verify hash field exists in webhook claim
   - Compute hash of request body
   - Verify computed hash matches token hash value
7. For empty request bodies:
   - Verify hash field is absent from webhook claim
8. Perform replay protection (verify jti not used)
```

## Best Practices

### Token Lifetime
- **Short validity period**: Typically no more than 15 minutes
- **Clock skew tolerance**: Approximately 60 seconds for time validation
- **Minimum TLS version**: TLS 1.2+ (TLS 1.3 recommended)

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