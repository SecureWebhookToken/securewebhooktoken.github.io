---
title: "SWT Specification (IETF Draft-03)"
description: "Complete technical specification of Secure Webhook Token (SWT) Draft-03: JWT header, webhook.hash binding, required claims, and A2A security."
---

## Overview

The Secure Webhook Token (SWT) is a specialized JSON Web Token (JWT) format designed for securely authorizing and verifying webhook requests. This specification defines the structure, transmission method, and validation requirements for SWT.

## JWT Structure

An SWT consists of the standard JWT components:

1. **Header**
2. **Payload**
3. **Signature**

### Header Requirements

The header MUST contain the following fields:

```json
{
  "alg": "HS256",
  "typ": "SWT",
  "kid": "key-2026-q4"
}
```

- **`alg`**: Signature algorithm (HS256, HS384, HS512, RS256, or ES256)
- **`typ`**: Token type (MUST be "SWT" to distinguish from generic JWTs)
- **`kid`** (Optional): Key ID identifying the public/symmetric key used for verification, enabling seamless key rotation and JWKS integration

### Payload Requirements (Claims)

#### Required Claims

- **`webhook`**: Custom claim containing:
  - **`event`**: String describing the webhook event type (e.g., "payment.received")
  - **`hash`**: Cryptographic hash of the request body (REQUIRED when body is non-empty, MUST be absent for empty bodies)
  - **`retry_count`**: (Optional) Non-negative integer indicating delivery attempt number (0 = initial, 1+ = retry)
- **`iss`** (Issuer): Token issuer identifier (URL or URN recommended)
- **`aud`** (Audience): Intended recipient endpoint or service identifier (REQUIRED in Draft-03 to prevent cross-service token reuse)
- **`exp`** (Expiration): Token expiration timestamp
- **`nbf`** (Not Before): Timestamp from when the token is valid
- **`iat`** (Issued At): Token creation timestamp
- **`jti`** (JWT ID): Unique token identifier (UUID recommended, required for replay defense)

#### Optional Claims

- **`sub`** (Subject): Subject identifier

#### Example Payload with Body Hash

```json
{
  "webhook": {
    "event": "user.created",
    "hash": "sha-256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "retry_count": 0
  },
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com/webhooks",
  "exp": 1703952000,
  "nbf": 1703948400,
  "iat": 1703948400,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "sub": "user-12345"
}
```

#### Example Payload without Body (Empty Request)

```json
{
  "webhook": {
    "event": "health.check"
  },
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com/webhooks",
  "exp": 1703952000,
  "nbf": 1703948400,
  "iat": 1703948400,
  "jti": "550e8400-e29b-41d4-a716-446655440001"
}
```

## Transmission Method

SWT tokens MUST be transmitted using HTTP POST with the token in the Authorization header using the Bearer scheme:

```http
POST /webhook-endpoint HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IlNXVCJ9...
Content-Type: application/json
Content-Length: 245

{
  "userId": "12345",
  "email": "user@example.com",
  "profile": {
    "name": "John Doe"
  }
}
```

## Hash Format and Algorithms

### Hash Format

The hash field follows the pattern: `"<algorithm>:<hex_value>"` where:
- **algorithm**: Standardized algorithm name (e.g., "sha-256", "sha-512")
- **hex_value**: Hexadecimal encoding of the hash (REQUIRED for interoperability)

### Supported Hash Algorithms

The specification supports the following hash algorithms:

- **SHA-2 family**: sha-256, sha-384, sha-512
- **SHA-3 family**: sha3-256, sha3-384, sha3-512

### Recommended Algorithms

**HS256, HS384, and HS512** (HMAC variants) are recommended for their balance between security and performance. RS256 and ES256 may be used when asymmetric cryptography is required.

## Security Requirements

### Transport Security

**HTTPS is REQUIRED** for all SWT transmissions. The minimum TLS version is 1.2, with TLS 1.3 recommended.

### Signature Verification

Receivers MUST verify the JWT signature before processing any claims. Implementations MUST:
- Maintain an allowlist of approved signature algorithms
- Reject tokens with non-approved algorithms, including "none"

### Replay Protection

Each `jti` value MUST only be accepted once within the token's validity period. Implementations should:
- Track used `jti` values
- Implement TTL-based cleanup to remove expired tokens from storage

### Time Validation

Implementations should:
- Allow approximately 60 seconds of clock skew tolerance
- Reject tokens where current time is before `nbf` or after `exp`
- Limit token lifetime to typically no more than 15 minutes

### Key Management

- **Symmetric keys**: Require minimum 256 bits of entropy
- **Private keys**: Implement appropriate access controls and secure storage

## Validation Workflow

Receivers MUST validate tokens in the following order:

1. Verify JWT signature and structure
2. Validate standard claims (`exp`, `nbf`, `iat`, `iss`, `jti`)
3. Confirm `webhook` claim exists and contains `event` field
4. For non-empty request bodies:
   - Verify `hash` field exists in `webhook` claim
   - Compute hash of request body
   - Verify computed hash matches token hash value
5. For empty request bodies:
   - Verify `hash` field is absent from `webhook` claim
6. Check replay protection (verify `jti` has not been used)

## Error Response Codes

Implementations SHOULD return appropriate HTTP status codes:

- **400 Bad Request**: Malformed token structure or hash mismatch
- **401 Unauthorized**: Signature verification failure or expired token
- **403 Forbidden**: Valid token but insufficient permissions or issuer/audience mismatch

## Autonomous AI Agent Workflows (A2A)

In autonomous agentic architectures and Model Context Protocol (MCP) environments, incoming webhooks deliver tool results or external event triggers directly into LLM context windows:

- **Indirect Prompt Injection Defense**: Because the request body is cryptographically bound to the signed token via `webhook.hash`, untrusted intermediaries cannot tamper with tool responses or inject malicious instructions into downstream agent reasoning loops.
- **Stateless Reactive Wakeup**: Agents in dormant, cost-saving states are only resumed when an authentic, unexpired token with matching `iss` and `aud` arrives.
- **Delegation Provenance**: The `iss` (caller identity), `aud` (target agent identity), and `retry_count` claims establish cross-boundary provenance for multi-agent delegation.