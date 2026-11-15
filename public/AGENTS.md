# AGENTS.md — Instructions for Coding Agents Integrating Secure Webhook Token (SWT)

- **Protocol**: IETF `draft-knauer-secure-webhook-token-03`
- **Full Context Bundle**: https://securewebhooktoken.github.io/llms-full.txt
- **Index**: https://securewebhooktoken.github.io/llms.txt
- **JSON Schema**: https://securewebhooktoken.github.io/schemas/swt-claims.schema.json

## Mandatory Verification Checklist

1. Require HTTP `POST` over HTTPS (TLS 1.2+ / 1.3) and `Authorization: Bearer <token>`.
2. Enforce JWT `alg` allowlist (`HS256`, `HS384`, `HS512`, `RS256`, `ES256`); reject `"none"`.
3. Require JWT header `typ === "SWT"`.
4. Verify `iss`, `aud`, `exp`, `nbf`, `iat`, and `jti` (with ~60s clock skew tolerance).
5. For non-empty bodies: compute raw body hash (`sha-256:<hex>` etc.) and compare in constant time against `webhook.hash`. For empty bodies: require `webhook.hash` to be absent.
6. Reject replayed `jti` values within the token validity window.
