---
title: "Create & Validate Secure Webhook Token"
---

```python
import jwt
import hashlib
import json
import time
import uuid

def create_swt(event, payload=None, secret=None, issuer='webhook-service.example.com',
               expires_in=300, subject=None, retry_count=None):
    """
    Create a Secure Webhook Token (SWT).

    Args:
        event: Webhook event type (e.g., 'user.created')
        payload: Request body data (dict or None for empty body)
        secret: Secret key for signing
        issuer: Token issuer identifier
        expires_in: Token lifetime in seconds (default: 300 = 5 minutes)
        subject: Optional subject identifier
        retry_count: Optional retry attempt number
    """
    now = int(time.time())

    claims = {
        'webhook': {
            'event': event
        },
        'iss': issuer,
        'exp': now + expires_in,
        'nbf': now,
        'iat': now,
        'jti': str(uuid.uuid4())
    }

    # Add optional subject
    if subject:
        claims['sub'] = subject

    # Add optional retry_count
    if retry_count is not None:
        claims['webhook']['retry_count'] = retry_count

    # Add payload hash if body is non-empty (REQUIRED by spec)
    if payload and len(payload) > 0:
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        hash_obj = hashlib.sha256(payload_str.encode('utf-8'))
        # Use standardized algorithm name with hyphen
        claims['webhook']['hash'] = f"sha-256:{hash_obj.hexdigest()}"

    # Sign with typ: 'SWT' in header
    return jwt.encode(claims, secret, algorithm='HS256', headers={'typ': 'SWT'})


def validate_swt(token, payload=None, secret=None, clock_skew=60):
    """
    Validate a Secure Webhook Token (SWT).

    Args:
        token: JWT token string
        payload: Request body data (dict or None for empty body)
        secret: Secret key for verification
        clock_skew: Clock skew tolerance in seconds (default: 60)
    """
    try:
        # Decode header to check token type
        header = jwt.get_unverified_header(token)
        if header.get('typ') != 'SWT':
            raise ValueError('Invalid token type - must be SWT')

        # Decode and validate JWT with algorithm allowlist
        decoded = jwt.decode(
            token,
            secret,
            algorithms=['HS256', 'HS384', 'HS512'],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'leeway': clock_skew  # Clock skew tolerance
            }
        )

        # Check required claims
        if 'webhook' not in decoded or 'event' not in decoded['webhook']:
            raise ValueError('Missing webhook.event claim')

        required_claims = ['iss', 'exp', 'nbf', 'iat', 'jti']
        for claim in required_claims:
            if claim not in decoded:
                raise ValueError(f'Missing required claim: {claim}')

        # Hash validation based on body presence
        has_body = payload and len(payload) > 0

        if has_body:
            # Non-empty body: hash field is REQUIRED
            if 'hash' not in decoded['webhook']:
                raise ValueError('Hash field required for non-empty body')

            algorithm, expected_hash = decoded['webhook']['hash'].split(':')
            payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)

            # Convert standardized algorithm name (e.g., 'sha-256') to Python name
            if algorithm == 'sha-256':
                actual_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
            elif algorithm == 'sha-384':
                actual_hash = hashlib.sha384(payload_str.encode('utf-8')).hexdigest()
            elif algorithm == 'sha-512':
                actual_hash = hashlib.sha512(payload_str.encode('utf-8')).hexdigest()
            else:
                raise ValueError(f'Unsupported hash algorithm: {algorithm}')

            if actual_hash != expected_hash:
                raise ValueError('Payload hash mismatch')
        else:
            # Empty body: hash field MUST be absent
            if 'hash' in decoded['webhook']:
                raise ValueError('Hash field must be absent for empty body')

        return decoded

    except jwt.InvalidTokenError as e:
        raise ValueError(f'SWT validation failed: {str(e)}')


# Example usage
if __name__ == '__main__':
    SECRET = 'your-secret-key'

    # Create token with payload
    token_with_payload = create_swt(
        event='user.created',
        payload={'userId': '12345', 'email': 'user@example.com'},
        secret=SECRET,
        subject='user-12345'
    )
    print(f"Token with payload: {token_with_payload}")

    # Create token without payload
    token_empty = create_swt(
        event='health.check',
        payload=None,
        secret=SECRET
    )
    print(f"Token without payload: {token_empty}")

    # Validate tokens
    validated = validate_swt(
        token_with_payload,
        payload={'userId': '12345', 'email': 'user@example.com'},
        secret=SECRET
    )
    print(f"Validated token: {validated}")
```