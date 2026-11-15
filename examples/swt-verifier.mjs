import crypto from 'node:crypto';

const ALLOWED_SIG_ALGS = new Set(['HS256', 'HS384', 'HS512']);
const ALLOWED_HASH_ALGS = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
  'sha3-256': 'sha3-256',
  'sha3-384': 'sha3-384',
  'sha3-512': 'sha3-512',
};

const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB limit

function b64urlDecode(str) {
  if (!/^[A-Za-z0-9_-]+$/.test(str)) {
    throw new Error('Malformed base64url segment');
  }
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

/**
 * Atomic in-memory replay store for single-process testing ONLY.
 * Distributed deployments MUST use atomic Redis SET NX EX or SQL INSERT ... ON CONFLICT.
 */
export class AtomicMemoryReplayStore {
  constructor() {
    this.seen = new Map();
  }
  reserve(scopeKey, ttlSeconds, nowSeconds) {
    for (const [k, exp] of this.seen.entries()) {
      if (exp <= nowSeconds) this.seen.delete(k);
    }
    if (this.seen.has(scopeKey)) return false;
    this.seen.set(scopeKey, nowSeconds + ttlSeconds);
    return true;
  }
}

export function verifySWTRequest({
  protocol = 'https:',
  method = 'POST',
  authorization = '',
  rawBody = '',
  keyResolver,
  expectedIssuer,
  expectedAudience,
  nowSeconds = Math.floor(Date.now() / 1000),
  clockSkewSeconds = 60,
  allowedAlgorithms = ALLOWED_SIG_ALGS,
  maxBodyBytes = MAX_BODY_BYTES,
  replayStore,
}) {
  const sigAllowlist = allowedAlgorithms instanceof Set ? allowedAlgorithms : new Set(allowedAlgorithms);
  if (protocol !== 'https:') return { valid: false, status: 400, reason: 'HTTPS required' };
  if (method !== 'POST') return { valid: false, status: 405, reason: 'Method must be POST' };
  if (Buffer.byteLength(rawBody, 'utf8') > maxBodyBytes) {
    return { valid: false, status: 413, reason: 'Body too large' };
  }
  if (!authorization.startsWith('Bearer ')) {
    return { valid: false, status: 401, reason: 'Missing Bearer token' };
  }

  const token = authorization.slice('Bearer '.length).trim();
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    return { valid: false, status: 400, reason: 'Malformed JWT structure' };
  }

  let header, payload;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
    payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  } catch {
    return { valid: false, status: 400, reason: 'Invalid JSON in JWT' };
  }

  // Algorithm allowlist BEFORE signature verification; reject "none"
  if (typeof header.alg !== 'string' || !ALLOWED_SIG_ALGS.has(header.alg) || !sigAllowlist.has(header.alg)) {
    return { valid: false, status: 401, reason: 'Unsupported or disallowed algorithm' };
  }
  if (header.typ !== 'SWT') {
    return { valid: false, status: 401, reason: 'Invalid typ header (must be SWT)' };
  }

  // Safe kid validation (alphanumeric, -, _ only; no URL/path lookup)
  if (header.kid !== undefined && (typeof header.kid !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(header.kid))) {
    return { valid: false, status: 400, reason: 'Invalid kid format' };
  }

  const secret = keyResolver(header.kid);
  if (!secret) return { valid: false, status: 401, reason: 'Unknown verification key' };

  const nodeHmacAlg = header.alg.replace('HS', 'sha');
  const expectedSig = crypto.createHmac(nodeHmacAlg, secret).update(`${parts[0]}.${parts[1]}`).digest();
  let actualSig;
  try {
    actualSig = b64urlDecode(parts[2]);
  } catch {
    return { valid: false, status: 401, reason: 'Malformed signature encoding' };
  }
  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) {
    return { valid: false, status: 401, reason: 'Invalid signature' };
  }

  // Standard required claims
  if (
    typeof payload.iss !== 'string' ||
    !payload.iss ||
    typeof payload.jti !== 'string' ||
    !payload.jti ||
    typeof payload.exp !== 'number' ||
    typeof payload.nbf !== 'number' ||
    typeof payload.iat !== 'number'
  ) {
    return { valid: false, status: 400, reason: 'Missing or invalid standard claims' };
  }

  // Time validation with clock skew leeway
  if (nowSeconds >= payload.exp + clockSkewSeconds) {
    return { valid: false, status: 401, reason: 'Token expired' };
  }
  if (nowSeconds < payload.nbf - clockSkewSeconds) {
    return { valid: false, status: 401, reason: 'Token not yet valid (nbf)' };
  }

  // Issuer & Audience checks
  if (expectedIssuer && payload.iss !== expectedIssuer) {
    return { valid: false, status: 403, reason: 'Issuer mismatch' };
  }
  if (expectedAudience) {
    const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audList.includes(expectedAudience)) {
      return { valid: false, status: 403, reason: 'Audience mismatch' };
    }
  }

  // Webhook claim validation
  const wh = payload.webhook;
  if (!wh || typeof wh !== 'object' || typeof wh.event !== 'string' || !wh.event) {
    return { valid: false, status: 400, reason: 'Missing webhook.event' };
  }
  if (wh.retry_count !== undefined && (!Number.isInteger(wh.retry_count) || wh.retry_count < 0)) {
    return { valid: false, status: 400, reason: 'Invalid webhook.retry_count' };
  }

  // Raw body hash verification BEFORE consuming replay jti
  const bodyBuf = Buffer.from(rawBody, 'utf8');
  if (bodyBuf.length > 0) {
    if (typeof wh.hash !== 'string') {
      return { valid: false, status: 400, reason: 'Missing webhook.hash for non-empty body' };
    }
    const colonIdx = wh.hash.indexOf(':');
    if (colonIdx <= 0) return { valid: false, status: 400, reason: 'Malformed webhook.hash' };
    const hashAlg = wh.hash.slice(0, colonIdx);
    const expectedHex = wh.hash.slice(colonIdx + 1);
    const nodeHashAlg = ALLOWED_HASH_ALGS[hashAlg];
    if (!nodeHashAlg) return { valid: false, status: 400, reason: 'Unsupported hash algorithm' };
    if (!/^[0-9a-f]+$/.test(expectedHex) || expectedHex.length % 2 !== 0) {
      return { valid: false, status: 400, reason: 'Malformed hex digest' };
    }
    const actualDigest = crypto.createHash(nodeHashAlg).update(bodyBuf).digest();
    const expectedDigest = Buffer.from(expectedHex, 'hex');
    if (actualDigest.length !== expectedDigest.length || !crypto.timingSafeEqual(actualDigest, expectedDigest)) {
      return { valid: false, status: 400, reason: 'Body hash mismatch' };
    }
  } else if (wh.hash !== undefined) {
    return { valid: false, status: 400, reason: 'webhook.hash must be absent for empty body' };
  }

  // Atomic replay protection scoped by issuer
  if (replayStore) {
    const ttl = Math.max(1, payload.exp - nowSeconds + clockSkewSeconds);
    const scopeKey = `${payload.iss}:${payload.jti}`;
    if (!replayStore.reserve(scopeKey, ttl, nowSeconds)) {
      return { valid: false, status: 401, reason: 'Replay detected (duplicate jti)' };
    }
  }

  return { valid: true, status: 200, payload };
}
// Conformance testing is executed via https://github.com/SecureWebhookToken/swt-conformance
