---
weight: 4
bookCollapseSection: false
title: "Webhook-Handler"
---

## Webhook-Handler (Express.js)

```javascript
const express = require('express');
const app = express();

app.use(express.json());

app.post('/webhook', (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ 
        error: 'Authorization header fehlt' 
      });
    }
    
    const validatedToken = validateSWT(token, req.body, process.env.WEBHOOK_SECRET);
    
    // Webhook verarbeiten
    processWebhook(validatedToken.webhook, req.body);
    
    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('Webhook-Validierung fehlgeschlagen:', error.message);
    res.status(401).json({ 
      error: 'Unauthorized', 
      message: error.message 
    });
  }
});

function processWebhook(webhookData, payload) {
  console.log(`Webhook Event: ${webhookData.event}`);
  console.log('Payload:', payload);
  
  // Hier würde die eigentliche Webhook-Logik stehen
  switch (webhookData.event) {
    case 'user.created':
      handleUserCreated(payload);
      break;
    case 'user.updated':
      handleUserUpdated(payload);
      break;
    default:
      console.log('Unbekanntes Event:', webhookData.event);
  }
}
```