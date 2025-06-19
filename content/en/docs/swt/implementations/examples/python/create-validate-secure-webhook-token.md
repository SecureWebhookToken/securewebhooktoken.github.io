---
weight: 1
bookFlatSection: false
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
        'exp': now + 300,  # Valid for 5 minutes
        'nbf': now,
        'iat': now,
        'jti': str(uuid.uuid4())
    }
    
    # Add payload hash if present
    if payload:
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        hash_obj = hashlib.sha256(payload_str.encode('utf-8'))
        claims['webhook']['hash'] = f"sha256:{hash_obj.hexdigest()}"
    
    return jwt.encode(claims, secret, algorithm='HS256')

def validate_swt(token, payload=None, secret=None):
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        
        # Check required claims
        required_claims = ['webhook', 'iss', 'exp', 'nbf', 'iat', 'jti']
        for claim in required_claims:
            if claim not in decoded:
                raise ValueError(f'Missing required claim: {claim}')
        
        # Validate payload hash if present
        if payload and 'hash' in decoded['webhook']:
            algorithm, expected_hash = decoded['webhook']['hash'].split(':')
            payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            
            if algorithm == 'sha256':
                actual_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
            else:
                raise ValueError(f'Unsupported hash algorithm: {algorithm}')
            
            if actual_hash != expected_hash:
                raise ValueError('Payload hash mismatch')
        
        return decoded
    
    except jwt.InvalidTokenError as e:
        raise ValueError(f'SWT validation failed: {str(e)}')
```