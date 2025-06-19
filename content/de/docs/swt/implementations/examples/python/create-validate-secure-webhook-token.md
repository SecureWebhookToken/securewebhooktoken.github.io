---
weight: 1
bookCollapseSection: false
title: "Create & Validate Secure Webhook Token"
---

# Create & Validate Secure Webhook Token

```python
import jwt
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta

def create_swt(webhook_data, payload=None, secret=None):
    now = int(time.time())
    
    claims = {
        'webhook': {
            'event': webhook_data['event'],
            'data': webhook_data.get('data', {})
        },
        'iss': 'webhook-service.example.com',
        'exp': now + 300,  # 5 Minuten gültig
        'nbf': now,
        'iat': now,
        'jti': str(uuid.uuid4())
    }
    
    # Payload-Hash hinzufügen falls vorhanden
    if payload:
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        hash_obj = hashlib.sha256(payload_str.encode('utf-8'))
        claims['webhook']['hash'] = f"sha256:{hash_obj.hexdigest()}"
    
    return jwt.encode(claims, secret, algorithm='HS256')

def validate_swt(token, payload=None, secret=None):
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        
        # Pflicht-Claims prüfen
        required_claims = ['webhook', 'iss', 'exp', 'nbf', 'iat', 'jti']
        for claim in required_claims:
            if claim not in decoded:
                raise ValueError(f'Fehlender Pflicht-Claim: {claim}')
        
        # Payload-Hash validieren falls vorhanden
        if payload and 'hash' in decoded['webhook']:
            algorithm, expected_hash = decoded['webhook']['hash'].split(':')
            payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            
            if algorithm == 'sha256':
                actual_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
            else:
                raise ValueError(f'Ununterstützter Hash-Algorithmus: {algorithm}')
            
            if actual_hash != expected_hash:
                raise ValueError('Payload-Hash stimmt nicht überein')
        
        return decoded
    
    except jwt.InvalidTokenError as e:
        raise ValueError(f'SWT-Validierung fehlgeschlagen: {str(e)}')
```