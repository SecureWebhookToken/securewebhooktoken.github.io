---
title: "Sicherheitsrichtlinien"
---

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
function validateTokenTiming(decoded, clockSkew = 60) {
  const now = Math.floor(Date.now() / 1000);

  // Uhrzeiten-Toleranz anwenden
  if (decoded.exp <= (now - clockSkew)) {
    throw new Error('Token ist abgelaufen');
  }

  if (decoded.nbf > (now + clockSkew)) {
    throw new Error('Token ist noch nicht gültig');
  }
}
```

### Signatur-Algorithmen
- **Pflicht**: Alle Tokens müssen signiert sein
- **Algorithmus-Whitelist**: Implementierungen MÜSSEN eine Whitelist genehmigter Algorithmen pflegen
- **"none" ablehnen**: Tokens mit Algorithmus "none" immer ablehnen
- **Empfohlene Algorithmen**: HS256, HS384, HS512 (HMAC-Varianten) für Balance zwischen Sicherheit und Performance
- **Alternative Algorithmen**: RS256, ES256 können verwendet werden, wenn asymmetrische Kryptographie erforderlich ist

## Validierungsanforderungen

Alle SWT-Tokens müssen via HTTP POST übertragen werden. Der Validierungs-Workflow ist:

```
1. JWT-Signatur und -Struktur verifizieren
2. Token-Typ als SWT verifizieren (typ: "SWT")
3. Standard-Claims validieren (exp, nbf, iat, iss, jti)
4. Algorithmus auf Whitelist prüfen ("none" ablehnen)
5. Bestätigen, dass webhook-Claim mit event-Feld existiert
6. Bei nicht-leerem Request-Body:
   - Verifizieren, dass Hash-Feld im webhook-Claim existiert
   - Hash des Request-Bodys berechnen
   - Verifizieren, dass berechneter Hash mit Token-Hash übereinstimmt
7. Bei leerem Request-Body:
   - Verifizieren, dass Hash-Feld im webhook-Claim fehlt
8. Replay-Schutz durchführen (verifizieren, dass jti nicht verwendet wurde)
```

## Best Practices

### Token-Lebensdauer
- **Kurze Gültigkeitsdauer**: Typischerweise maximal 15 Minuten
- **Uhrzeiten-Toleranz**: Etwa 60 Sekunden für Zeitvalidierung
- **Minimale TLS-Version**: TLS 1.2+ (TLS 1.3 empfohlen)

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