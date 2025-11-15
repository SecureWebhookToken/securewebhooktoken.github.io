---
weight: 1
bookCollapseSection: false
title: "Client-side Token Generation"
---

## Client-side Token Generation

```javascript
// Send webhook with POST (required by SWT specification)
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

// Example usage with payload
sendWebhook(
  'https://api.example.com/webhook',
  'user.created',
  { userId: '12345', email: 'user@example.com' },
  'your-secret-key'
);

// Example usage without payload (empty body)
sendWebhook(
  'https://api.example.com/webhook',
  'health.check',
  null,
  'your-secret-key'
);
```