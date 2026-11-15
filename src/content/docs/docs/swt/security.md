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

### Atomic Replay Protection (`jti`)

An in-memory `Set` or `Map` is **not sufficient** for distributed or multi-worker production deployments and is vulnerable to time-of-check/time-of-use (TOCTOU) race conditions under concurrent webhook deliveries.

Production receivers MUST:
- **Reserve `jti` atomically** (single compare-and-set operation) rather than separate read-then-write checks.
- **Scope keys by issuer** (e.g., `swt:jti:<iss>:<jti>`) to prevent cross-issuer collisions.
- **Retain keys for the full acceptance window**: `TTL = max(1, (exp - now) + clockSkewSeconds)`.
- **Use a distributed store** (e.g., Redis or SQL database) shared across all receiver instances.
- **Fail closed** when replay protection is mandatory and the replay store is unavailable (return `503 Service Unavailable` rather than bypassing replay checks).

#### Redis Atomic Reservation Example

```javascript
// Atomic reservation via Redis SET NX EX
async function reserveJtiRedis(redis, iss, jti, exp, clockSkew = 60) {
  const now = Math.floor(Date.now() / 1000);
  const ttlSeconds = Math.max(1, exp - now + clockSkew);
  const key = `swt:jti:${iss}:${jti}`;

  // Returns "OK" only if the key did not exist; null on replay or concurrent duplicate
  const reserved = await redis.set(key, '1', 'EX', ttlSeconds, 'NX');
  if (reserved !== 'OK') {
    throw new Error('Token replay detected (jti already used)');
  }
}
```

#### PostgreSQL Atomic Reservation Example

```sql
-- Atomic reservation table
CREATE TABLE IF NOT EXISTS swt_used_jti (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (iss, jti)
);

-- Single atomic statement: 0 rows returned means replay or concurrent duplicate
INSERT INTO swt_used_jti (iss, jti, expires_at)
VALUES ($1, $2, to_timestamp($3))
ON CONFLICT (iss, jti) DO NOTHING
RETURNING jti;
```

### Retry Semantics vs. Event Idempotency

Do not confuse **token replay protection** with **application-level event idempotency**:
- **Token replay protection (`jti`)**: Per Draft-03 Section 7.9, each webhook retry MUST mint a fresh SWT with a **new, unique `jti`** and updated `webhook.retry_count` (e.g., `0`, `1`, `2`). Reusing an old token on retry is a replay and MUST be rejected.
- **Application event idempotency**: If your application must process a logical webhook event at most once across legitimate retries, deduplicate on a domain-level event identifier (for example, an `event_id` in the JSON body or an `Idempotency-Key` header) after the SWT signature, body hash, and `jti` checks succeed.

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
- **Short validity period**: Typically no more than 15 minutes (`exp - iat <= 900s`, implementation guidance)
- **Clock skew tolerance**: Approximately 60 seconds for time validation (implementation guidance, not a hard protocol constant)
- **Minimum TLS version**: TLS 1.2+ (TLS 1.3 recommended)

### AI Agent Trust Boundaries
- SWT provides **cryptographic sender authenticity and payload integrity**, ensuring tampered or unauthenticated payloads are rejected before reaching an LLM or agent tool.
- SWT does **not** sanitize malicious instructions originating from an authorized sender and does not replace prompt-injection defenses, content validation, or agent authorization policies.

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