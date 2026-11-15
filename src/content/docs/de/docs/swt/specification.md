---
title: "Spezifikation"
---

## Überblick

Der Secure Webhook Token (SWT) ist ein spezialisiertes JSON Web Token (JWT)-Format, das für die sichere Autorisierung und Verifizierung von Webhook-Anfragen entwickelt wurde. Diese Spezifikation definiert die Struktur, Übertragungsmethode und Validierungsanforderungen für SWT.

## JWT-Struktur

Ein SWT besteht aus den standardmäßigen JWT-Komponenten:

1. **Header** (Kopfzeile)
2. **Payload** (Nutzdaten)
3. **Signature** (Signatur)

### Header-Anforderungen

Der Header MUSS folgende Felder enthalten:

```json
{
  "alg": "HS256",
  "typ": "SWT",
  "kid": "key-2026-q4"
}
```

- **`alg`**: Signaturalgorithmus (HS256, HS384, HS512, RS256 oder ES256)
- **`typ`**: Token-Typ (MUSS "SWT" sein, um sich von generischen JWTs zu unterscheiden)
- **`kid`** (Optional): Key-ID zur Identifikation des Schlüssels bei dynamischer Schlüsselrotation und JWKS

### Payload-Anforderungen (Claims)

#### Pflicht-Claims

- **`webhook`**: Benutzerdefinierter Claim mit:
  - **`event`**: String, der den Webhook-Ereignistyp beschreibt (z.B. "payment.received")
  - **`hash`**: Kryptographischer Hash des Request-Bodys (ERFORDERLICH bei nicht-leerem Body, MUSS bei leerem Body fehlen)
  - **`retry_count`**: (Optional) Nicht-negative Ganzzahl für Zustellungsversuche (0 = Initial, 1+ = Retry)
- **`iss`** (Issuer): Token-Aussteller-Identifikator
- **`aud`** (Audience): Autorisierter Ziel-Empfänger bzw. Endpoint (ERFORDERLICH in Draft-03 zur Verhinderung von Cross-Service-Replay)
- **`exp`** (Expiration): Token-Ablaufzeitstempel
- **`nbf`** (Not Before): Zeitstempel, ab wann das Token gültig ist
- **`iat`** (Issued At): Zeitstempel der Token-Erstellung
- **`jti`** (JWT ID): Eindeutige Token-Identifikation (UUID empfohlen, zwingend für Replay-Schutz)

#### Optionale Claims

- **`sub`** (Subject): Subjekt-Identifikator

#### Beispiel Payload mit Body-Hash

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

#### Beispiel Payload ohne Body (Leere Anfrage)

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

## Übertragungsmethode

SWT-Tokens MÜSSEN mittels HTTP POST übertragen werden, wobei das Token im Authorization-Header mit dem Bearer-Schema verwendet wird:

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
    "name": "Max Mustermann"
  }
}
```

## Hash-Format und -Algorithmen

### Hash-Format

Das Hash-Feld folgt dem Muster: `"<algorithmus>:<hex_wert>"` wobei:
- **algorithmus**: Standardisierter Algorithmusname (z.B. "sha-256", "sha-512")
- **hex_wert**: Hexadezimale Kodierung des Hashes (ERFORDERLICH für Interoperabilität)

### Unterstützte Hash-Algorithmen

Die Spezifikation unterstützt folgende Hash-Algorithmen:

- **SHA-2 Familie**: sha-256, sha-384, sha-512
- **SHA-3 Familie**: sha3-256, sha3-384, sha3-512

### Empfohlene Algorithmen

**HS256, HS384 und HS512** (HMAC-Varianten) werden aufgrund ihrer Balance zwischen Sicherheit und Performance empfohlen. RS256 und ES256 können verwendet werden, wenn asymmetrische Kryptographie erforderlich ist.

## Sicherheitsanforderungen

### Transportsicherheit

**HTTPS ist ERFORDERLICH** für alle SWT-Übertragungen. Die minimale TLS-Version ist 1.2, TLS 1.3 wird empfohlen.

### Signaturverifizierung

Empfänger MÜSSEN die JWT-Signatur verifizieren, bevor Claims verarbeitet werden. Implementierungen MÜSSEN:
- Eine Whitelist genehmigter Signaturalgorithmen pflegen
- Tokens mit nicht-genehmigten Algorithmen ablehnen, einschließlich "none"

### Replay-Schutz

Jeder `jti`-Wert MUSS nur einmal innerhalb der Token-Gültigkeitsdauer akzeptiert werden. Implementierungen sollten:
- Verwendete `jti`-Werte nachverfolgen
- TTL-basierte Bereinigung implementieren, um abgelaufene Tokens aus dem Speicher zu entfernen

### Zeitvalidierung

Implementierungen sollten:
- Etwa 60 Sekunden Uhrzeiten-Toleranz zulassen
- Tokens ablehnen, bei denen die aktuelle Zeit vor `nbf` oder nach `exp` liegt
- Token-Lebensdauer typischerweise auf maximal 15 Minuten begrenzen

### Schlüsselverwaltung

- **Symmetrische Schlüssel**: Mindestens 256 Bits Entropie erforderlich
- **Private Schlüssel**: Angemessene Zugriffskontrollen und sichere Speicherung implementieren

## Validierungs-Workflow

Empfänger MÜSSEN Tokens in folgender Reihenfolge validieren:

1. JWT-Signatur und -Struktur verifizieren
2. Standard-Claims validieren (`exp`, `nbf`, `iat`, `iss`, `jti`)
3. Bestätigen, dass `webhook`-Claim existiert und `event`-Feld enthält
4. Bei nicht-leerem Request-Body:
   - Verifizieren, dass `hash`-Feld im `webhook`-Claim existiert
   - Hash des Request-Bodys berechnen
   - Verifizieren, dass berechneter Hash mit Token-Hash-Wert übereinstimmt
5. Bei leerem Request-Body:
   - Verifizieren, dass `hash`-Feld im `webhook`-Claim fehlt
6. Replay-Schutz prüfen (verifizieren, dass `jti` noch nicht verwendet wurde)

## Fehler-Response-Codes

Implementierungen SOLLTEN entsprechende HTTP-Statuscodes zurückgeben:

- **400 Bad Request**: Fehlerhaft formatiertes Token oder Hash-Fehlanpassung
- **401 Unauthorized**: Signaturverifizierung fehlgeschlagen oder Token abgelaufen
- **403 Forbidden**: Gültiges Token, aber unzureichende Berechtigungen oder Issuer/Audience-Diskrepanz

## Autonome KI-Agenten-Workflows (A2A)

In autonomen Multi-Agenten-Architekturen und Model Context Protocol (MCP) Umgebungen leiten Webhooks asynchrone Tool-Ergebnisse oder Event-Trigger direkt in die Context-Windows von LLMs:

- **Schutz vor Indirect Prompt Injection**: Durch die kryptographische Bindung des Request-Bodys via `webhook.hash` an das signierte JWT können Angreifer keine manipulierten Daten oder bösartigen Prompts in nachgelagerte Reasoning-Loops einschleusen.
- **Stateless Reactive Wakeup**: Ruhende, kostensparende Agenten werden nur dann aufgeweckt, wenn ein authentisches, gültiges Token mit passendem `iss` und `aud` empfangen wird.
- **Delegations-Herkunft (Provenance)**: `iss` (Identität des Senders), `aud` (Identität des Ziel-Agenten) und `retry_count` etablieren eine lückenlose Audit-Chain über Vertrauensgrenzen hinweg.