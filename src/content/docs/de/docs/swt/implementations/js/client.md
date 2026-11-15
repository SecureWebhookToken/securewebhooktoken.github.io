---
title: "Client-seitige Token-Generierung"
---

## Client-seitige Token-Generierung

```javascript
// Webhook mit POST senden (erforderlich gemäß SWT-Spezifikation)
function sendWebhook(endpoint, event, payload, secret) {
  const token = createSWT(event, payload, secret);

  return fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: payload ? JSON.stringify(payload) : ''
  });
}

// Beispiel-Verwendung mit Payload
sendWebhook(
  'https://api.example.com/webhook',
  'user.created',
  { userId: '12345', email: 'user@example.com' },
  'your-secret-key'
);

// Beispiel-Verwendung ohne Payload (leerer Body)
sendWebhook(
  'https://api.example.com/webhook',
  'health.check',
  null,
  'your-secret-key'
);
```