---
weight: 20
title: "Sicherheitsrichtlinien"
---

# Sicherheitsrichtlinien

## Transport-Sicherheit

### HTTPS verwenden
Alle Webhook-Kommunikation muss über HTTPS erfolgen. HTTP-Verbindungen sind nicht zulässig.

### TLS-Anforderungen
- **Mindestanforderung**: TLS 1.2+
- **Empfohlen**: TLS 1.3 für optimale Sicherheit

## Token-Sicherheit

### Replay-Schutz implementieren
```javascript
// Beispiel: JTI-basierter Replay-Schutz
const usedTokens = new Set();

function checkReplayProtection(jti) {
  if (usedTokens.has(jti)) {
    throw new Error('Token bereits verwendet (Replay-Angriff)');
  }
  usedTokens.add(jti);
}
```

### Token-Ablauf validieren
```javascript
function validateTokenTiming(decoded) {
  const now = Math.floor(Date.now() / 1000);
  
  if (decoded.exp <= now) {
    throw new Error('Token ist abgelaufen');
  }
  
  if (decoded.nbf > now) {
    throw new Error('Token ist noch nicht gültig');
  }
}
```

### JSON Web Signatures (JWS)
- **Pflicht**: Alle Tokens müssen signiert sein
- **Empfohlene Algorithmen**: HS256, RS256, ES256

### JSON Web Encryption (JWE)
- **Optional**: Für sensible Daten empfohlen
- **Algorithmen**: A256GCM, A256CBC-HS512

## Validierungsanforderungen

### HEAD-Anfragen
```
1. JWT-Signatur validieren
2. Token-Ablauf prüfen  
3. Issuer verifizieren
4. Replay-Schutz durchführen
```

### POST-Anfragen  
```
1. JWT-Signatur validieren
2. Token-Ablauf prüfen
3. Payload-Hash verifizieren
4. Content-Length validieren
5. Replay-Schutz durchführen
```

## Best Practices

### Token-Lebensdauer
- **Kurze Gültigkeitsdauer**: Maximal 5-15 Minuten
- **Angemessene nbf-Zeit**: 1-2 Minuten vor aktueller Zeit für Clock-Skew

### Replay-Schutz
- **JTI-Tracking**: Bereits verwendete Token-IDs speichern
- **TTL-basierte Bereinigung**: Alte JTIs automatisch entfernen

```javascript
// Beispiel: TTL-basierte JTI-Bereinigung
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

### Monitoring und Logging
- **Fehlgeschlagene Validierungen protokollieren**
- **Verdächtige Aktivitäten überwachen**  
- **Token-Verwendungsstatistiken erfassen**

```javascript
// Beispiel: Sicherheits-Logging
function logSecurityEvent(event, details) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: event,
    details: details,
    severity: event.includes('failed') ? 'HIGH' : 'INFO'
  }));
}
```