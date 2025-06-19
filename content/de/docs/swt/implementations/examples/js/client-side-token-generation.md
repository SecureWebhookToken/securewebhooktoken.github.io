---
weight: 1
bookCollapseSection: false
title: "Client-seitige Token-Generierung"
---

## Client-seitige Token-Generierung

```javascript
// Für HEAD-Requests (kleine Payloads)
function sendWebhookHEAD(endpoint, webhookData, secret) {
  const token = createSWT(webhookData, null, secret);
  
  return fetch(endpoint, {
    method: 'HEAD',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
}

// Für POST-Requests (größere Payloads)
function sendWebhookPOST(endpoint, webhookData, payload, secret) {
  const token = createSWT(webhookData, payload, secret);
  
  return fetch(endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
}
```