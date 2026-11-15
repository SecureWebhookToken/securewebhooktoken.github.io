---
title: "SWT Sicherheitsrichtlinien & Best Practices"
description: "Sicherheitsrichtlinien für Secure Webhook Tokens: TLS-Anforderungen, Algorithmus-Allowlist, JTI-Replay-Schutz, Clock-Skew-Toleranz und Logging."
---

## Transport-Sicherheit

### HTTPS verwenden
Alle Webhook-Kommunikation muss über HTTPS erfolgen. HTTP-Verbindungen sind nicht zulässig.

### TLS-Anforderungen
- **Mindestanforderung**: TLS 1.2+
- **Empfohlen**: TLS 1.3 für optimale Sicherheit

## Token-Sicherheit

### Atomarer Replay-Schutz (`jti`)

Ein In-Memory-`Set` oder -`Map` ist für verteilte oder Multi-Worker-Produktionsumgebungen **nicht ausreichend** und anfällig für TOCTOU-Race-Conditions bei gleichzeitigen Webhook-Zustellungen.

Produktive Empfänger MÜSSEN:
- **`jti` atomar reservieren** (einzelne Compare-and-Set-Operation statt separatem Lesen und Schreiben).
- **Schlüssel nach Issuer trennen** (z. B. `swt:jti:<iss>:<jti>`), um Kollisionen zwischen Ausstellern zu vermeiden.
- **Schlüssel über das gesamte Akzeptanzfenster speichern**: `TTL = max(1, (exp - now) + clockSkewSeconds)`.
- **Einen verteilten Speicher nutzen** (z. B. Redis oder SQL-Datenbank), der von allen Empfänger-Instanzen geteilt wird.
- **Fail-Closed reagieren**, wenn Replay-Schutz verpflichtend ist und der Speicher nicht erreichbar ist (`503 Service Unavailable` statt Umgehung der Prüfung).

#### Redis-Beispiel (atomare Reservierung)

```javascript
// Atomare Reservierung via Redis SET NX EX
async function reserveJtiRedis(redis, iss, jti, exp, clockSkew = 60) {
  const now = Math.floor(Date.now() / 1000);
  const ttlSeconds = Math.max(1, exp - now + clockSkew);
  const key = `swt:jti:${iss}:${jti}`;

  // Gibt nur "OK" zurück, wenn der Key noch nicht existierte; null bei Replay/Duplikat
  const reserved = await redis.set(key, '1', 'EX', ttlSeconds, 'NX');
  if (reserved !== 'OK') {
    throw new Error('Token-Replay erkannt (jti bereits verwendet)');
  }
}
```

#### PostgreSQL-Beispiel (atomare Reservierung)

```sql
CREATE TABLE IF NOT EXISTS swt_used_jti (
  iss TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (iss, jti)
);

-- Atomare Einzelanweisung: 0 Zeilen bedeutet Replay oder gleichzeitiges Duplikat
INSERT INTO swt_used_jti (iss, jti, expires_at)
VALUES ($1, $2, to_timestamp($3))
ON CONFLICT (iss, jti) DO NOTHING
RETURNING jti;
```

### Retry-Semantik vs. Event-Idempotenz

Unterscheiden Sie klar zwischen **Token-Replay-Schutz** und **anwendungsseitiger Event-Idempotenz**:
- **Token-Replay-Schutz (`jti`)**: Gemäß Draft-03 Abschnitt 7.9 MUSS jeder Webhook-Retry ein frisches SWT mit einer **neuen, eindeutigen `jti`** und aktualisiertem `webhook.retry_count` (`0`, `1`, `2`, …) erzeugen. Die Wiederverwendung eines alten Tokens bei einem Retry ist ein Replay und MUSS abgelehnt werden.
- **Event-Idempotenz**: Wenn Ihre Anwendung ein logisches Webhook-Event über legitime Retries hinweg höchstens einmal verarbeiten darf, deduplizieren Sie über eine fachliche Event-ID (z. B. im JSON-Body oder `Idempotency-Key`-Header), nachdem Signatur, Body-Hash und `jti` erfolgreich geprüft wurden.

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
- **Kurze Gültigkeitsdauer**: Typischerweise maximal 15 Minuten (`exp - iat <= 900s`, Implementierungsempfehlung)
- **Uhrzeiten-Toleranz**: Etwa 60 Sekunden für Zeitvalidierung (Implementierungsempfehlung, kein starrer Protokollwert)
- **Minimale TLS-Version**: TLS 1.2+ (TLS 1.3 empfohlen)

### Vertrauensgrenzen für KI-Agenten
- SWT liefert **kryptographische Sender-Authentizität und Payload-Integrität**, sodass manipulierte oder unauthentifizierte Payloads abgelehnt werden, bevor sie ein LLM oder Agenten-Tool erreichen.
- SWT bereinigt **keine** bösartigen Anweisungen eines autorisierten Senders und ersetzt weder Prompt-Injection-Filter noch Inhaltsvalidierung oder Autorisierungsrichtlinien.

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