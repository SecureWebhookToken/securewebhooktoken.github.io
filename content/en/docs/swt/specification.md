---
weight: 10
title: "Specification"
---

# Specification

## Overview

Secure Webhook Token (SWT) is a specialized implementation of JSON Web Tokens (JWT) designed for secure authorization of webhook requests. The specification is designed to be lightweight, flexible, and compatible with standard JWT structures.

## JWT Structure

An SWT consists of the standard JWT components:

1. **Header**
2. **Payload**  
3. **Signature**

### Header Requirements

The header must contain the following fields:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- `alg`: Signature algorithm (typically "HS256")
- `typ`: Token type (must be "JWT")

### Payload Requirements (Claims)

#### Required Claims

- **`webhook`**: Custom claim with `event` and optional `data`
- **`iss`** (Issuer): Token issuer
- **`exp`** (Expiration): Token expiration time  
- **`nbf`** (Not Before): Timestamp from when the token is valid
- **`iat`** (Issued At): Token creation timestamp
- **`jti`** (JWT ID): Unique token identification

#### Example Payload

```json
{
  "webhook": {
    "event": "user.created",
    "data": {
      "userId": "12345", 
      "email": "user@example.com"
    }
  },
  "iss": "webhook-service.example.com",
  "exp": 1703952000,
  "nbf": 1703948400, 
  "iat": 1703948400,
  "jti": "unique-token-id-123"
}
```

## Transmission Methods

### HEAD Method (Recommended)

For JSON payloads ≤ 6kB, the HEAD method is recommended:

```http
HEAD /webhook-endpoint HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Content-Length: 245
```

### POST Method

For larger payloads or non-JSON content:

```http
POST /webhook-endpoint HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Content-Length: 8192

{
  "userId": "12345",
  "email": "user@example.com", 
  "profile": {
    "name": "John Doe",
    "address": "..."
  }
}
```

## Hash Algorithms

The specification supports the following hash algorithms for payload validation:

- **SHA-2 family**: sha256, sha384, sha512
- **SHA-3 family**: sha3-256, sha3-384, sha3-512

### Example with Payload Hash

```json
{
  "webhook": {
    "event": "user.updated",
    "hash": "sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  },
  "iss": "webhook-service.example.com",
  "exp": 1703952000,
  "iat": 1703948400,
  "jti": "token-456"
}
```