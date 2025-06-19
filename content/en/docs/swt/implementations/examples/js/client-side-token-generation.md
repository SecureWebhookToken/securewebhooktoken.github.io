---
weight: 1
bookCollapseSection: false
title: "Client-side Token Generation"
---

## Client-side Token Generation

```javascript
// For HEAD requests (small payloads)
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

// For POST requests (larger payloads)
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