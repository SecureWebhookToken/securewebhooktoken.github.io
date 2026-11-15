---
title: "Python: SWT erstellen & validieren"
description: "Implementiere Secure Webhook Token Generierung und Verifizierung in Python mit PyJWT und hashlib für SHA-256-Body-Bindung und Replay-Schutz."
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
    Erstellt einen Secure Webhook Token (SWT).

    Args:
        event: Webhook-Ereignistyp (z.B. 'user.created')
        payload: Request-Body-Daten (dict oder None für leeren Body)
        secret: Geheimer Schlüssel zur Signierung
        issuer: Token-Aussteller-Identifikator
        expires_in: Token-Lebensdauer in Sekunden (Standard: 300 = 5 Minuten)
        subject: Optionaler Subject-Identifikator
        retry_count: Optionale Wiederholungsversuchsnummer
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

    # Optionales Subject hinzufügen
    if subject:
        claims['sub'] = subject

    # Optionalen retry_count hinzufügen
    if retry_count is not None:
        claims['webhook']['retry_count'] = retry_count

    # Payload-Hash hinzufügen, wenn Body nicht-leer ist (ERFORDERLICH gemäß Spezifikation)
    if payload and len(payload) > 0:
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        hash_obj = hashlib.sha256(payload_str.encode('utf-8'))
        # Standardisierten Algorithmusnamen mit Bindestrich verwenden
        claims['webhook']['hash'] = f"sha-256:{hash_obj.hexdigest()}"

    # Mit typ: 'SWT' im Header signieren
    return jwt.encode(claims, secret, algorithm='HS256', headers={'typ': 'SWT'})


def validate_swt(token, payload=None, secret=None, clock_skew=60):
    """
    Validiert einen Secure Webhook Token (SWT).

    Args:
        token: JWT-Token-String
        payload: Request-Body-Daten (dict oder None für leeren Body)
        secret: Geheimer Schlüssel zur Verifizierung
        clock_skew: Uhrzeiten-Toleranz in Sekunden (Standard: 60)
    """
    try:
        # Header dekodieren, um Token-Typ zu prüfen
        header = jwt.get_unverified_header(token)
        if header.get('typ') != 'SWT':
            raise ValueError('Ungültiger Token-Typ - muss SWT sein')

        # JWT mit Algorithmus-Whitelist dekodieren und validieren
        decoded = jwt.decode(
            token,
            secret,
            algorithms=['HS256', 'HS384', 'HS512'],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'leeway': clock_skew  # Uhrzeiten-Toleranz
            }
        )

        # Pflicht-Claims prüfen
        if 'webhook' not in decoded or 'event' not in decoded['webhook']:
            raise ValueError('Fehlender webhook.event Claim')

        required_claims = ['iss', 'exp', 'nbf', 'iat', 'jti']
        for claim in required_claims:
            if claim not in decoded:
                raise ValueError(f'Fehlender Pflicht-Claim: {claim}')

        # Hash-Validierung basierend auf Body-Vorhandensein
        has_body = payload and len(payload) > 0

        if has_body:
            # Nicht-leerer Body: Hash-Feld ist ERFORDERLICH
            if 'hash' not in decoded['webhook']:
                raise ValueError('Hash-Feld erforderlich für nicht-leeren Body')

            algorithm, expected_hash = decoded['webhook']['hash'].split(':')
            payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True)

            # Standardisierten Algorithmusnamen konvertieren (z.B. 'sha-256') zu Python-Namen
            if algorithm == 'sha-256':
                actual_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()
            elif algorithm == 'sha-384':
                actual_hash = hashlib.sha384(payload_str.encode('utf-8')).hexdigest()
            elif algorithm == 'sha-512':
                actual_hash = hashlib.sha512(payload_str.encode('utf-8')).hexdigest()
            else:
                raise ValueError(f'Ununterstützter Hash-Algorithmus: {algorithm}')

            if actual_hash != expected_hash:
                raise ValueError('Payload-Hash stimmt nicht überein')
        else:
            # Leerer Body: Hash-Feld MUSS fehlen
            if 'hash' in decoded['webhook']:
                raise ValueError('Hash-Feld muss bei leerem Body fehlen')

        return decoded

    except jwt.InvalidTokenError as e:
        raise ValueError(f'SWT-Validierung fehlgeschlagen: {str(e)}')


# Beispiel-Verwendung
if __name__ == '__main__':
    SECRET = 'your-secret-key'

    # Token mit Payload erstellen
    token_with_payload = create_swt(
        event='user.created',
        payload={'userId': '12345', 'email': 'user@example.com'},
        secret=SECRET,
        subject='user-12345'
    )
    print(f"Token mit Payload: {token_with_payload}")

    # Token ohne Payload erstellen
    token_empty = create_swt(
        event='health.check',
        payload=None,
        secret=SECRET
    )
    print(f"Token ohne Payload: {token_empty}")

    # Token validieren
    validated = validate_swt(
        token_with_payload,
        payload={'userId': '12345', 'email': 'user@example.com'},
        secret=SECRET
    )
    print(f"Validierter Token: {validated}")
```