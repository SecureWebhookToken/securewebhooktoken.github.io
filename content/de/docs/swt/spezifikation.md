---
weight: 10
title: "Spezifikation"
---

# Spezifikation

## Überblick

Secure Webhook Token (SWT) ist eine spezialisierte Implementierung von JSON Web Tokens (JWT), die für die sichere Autorisierung von Webhook-Anfragen entwickelt wurde. Die Spezifikation ist darauf ausgelegt, leichtgewichtig, flexibel und kompatibel mit Standard-JWT-Strukturen zu sein.

## JWT-Struktur

Ein SWT besteht aus den standardmäßigen JWT-Komponenten:

1. **Header** (Kopfzeile)
2. **Payload** (Nutzdaten)  
3. **Signature** (Signatur)

### Header-Anforderungen

Der Header muss folgende Felder enthalten:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- `alg`: Signaturalgorithmus (typischerweise "HS256")
- `typ`: Token-Typ (muss "JWT" sein)

### Payload-Anforderungen (Claims)

#### Pflicht-Claims

- **`webhook`**: Benutzerdefinierter Claim mit `event` und optionalen `data`
- **`iss`** (Issuer): Aussteller des Tokens
- **`exp`** (Expiration): Ablaufzeit des Tokens  
- **`nbf`** (Not Before): Zeitstempel, ab wann das Token gültig ist
- **`iat`** (Issued At): Zeitstempel der Token-Erstellung
- **`jti`** (JWT ID): Eindeutige Token-Identifikation

#### Beispiel Payload

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

## Übertragungsmethoden

### HEAD-Methode (Empfohlen)

Für JSON-Nutzdaten ≤ 6kB wird die HEAD-Methode empfohlen:

```http
HEAD /webhook-endpoint HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Content-Length: 245
```

### POST-Methode

Für größere Nutzdaten oder Nicht-JSON-Inhalte:

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
    "name": "Max Mustermann",
    "address": "..."
  }
}
```

## Hash-Algorithmen

Die Spezifikation unterstützt folgende Hash-Algorithmen für die Payload-Validierung:

- **SHA-2 Familie**: sha256, sha384, sha512
- **SHA-3 Familie**: sha3-256, sha3-384, sha3-512

### Beispiel mit Payload-Hash

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