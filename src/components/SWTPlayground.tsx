import React, { useEffect, useMemo, useState } from 'react';
import './SWTPlayground.css';

type Alg = 'HS256' | 'HS384' | 'HS512';
type HashAlg = 'sha-256' | 'sha-384' | 'sha-512';

interface Props {
  locale?: 'en' | 'de';
}

interface Preset {
  id: string;
  labelEn: string;
  labelDe: string;
  event: string;
  iss: string;
  aud: string;
  body: string;
}

const PRESETS: Preset[] = [
  {
    id: 'agent',
    labelEn: 'AI Agent Callback',
    labelDe: 'KI-Agenten-Callback',
    event: 'agent.tool.completed',
    iss: 'https://mcp-gateway.example.com',
    aud: 'https://orchestrator.example.com/a2a/webhook',
    body: JSON.stringify(
      {
        taskId: 'task_9f82c1',
        agentId: 'research-agent-01',
        status: 'completed',
        output: { summary: 'Verified IETF Draft-03 specification', confidence: 0.99 },
      },
      null,
      2
    ),
  },
  {
    id: 'payment',
    labelEn: 'Payment Event',
    labelDe: 'Zahlungs-Event',
    event: 'payment.received',
    iss: 'https://billing.example.com',
    aud: 'https://api.example.com/webhooks',
    body: JSON.stringify(
      {
        paymentId: 'pay_8472910',
        amount: 149.0,
        currency: 'EUR',
        customer: 'cus_9912',
      },
      null,
      2
    ),
  },
  {
    id: 'empty',
    labelEn: 'Empty Body (Health Check)',
    labelDe: 'Leerer Body (Health Check)',
    event: 'health.check',
    iss: 'https://monitor.example.com',
    aud: 'https://api.example.com/webhooks',
    body: '',
  },
];

const TEXT = {
  en: {
    presets: 'Presets:',
    tamper: 'Tamper Body',
    resign: 'Re-sign Token',
    newJti: 'New JTI',
    alg: 'Algorithm',
    hashAlg: 'Body Hash Alg',
    kid: 'Key ID (kid)',
    event: 'Webhook Event',
    issuer: 'Issuer (iss)',
    audience: 'Audience (aud)',
    jti: 'Token ID (jti)',
    secret: 'HMAC Secret Key',
    body: 'HTTP POST Request Body',
    bodyEmptyHint: 'Empty body: webhook.hash MUST be absent per Draft-03.',
    encodedToken: 'Encoded Secure Webhook Token (SWT)',
    copyToken: 'Copy Token',
    copied: 'Copied!',
    copyCurl: 'Copy cURL',
    validTitle: 'Valid SWT — Signature & Body Hash Verified',
    invalidTitle: 'Verification Failed',
    sigCheck: 'Signature',
    typCheck: 'typ: "SWT"',
    hashCheck: 'Body Hash',
    claimsCheck: 'Claims',
    pass: 'PASS',
    fail: 'FAIL',
    decodedHeader: 'Decoded Header',
    decodedPayload: 'Decoded Payload',
    tamperReason: 'Body was modified after signing (webhook.hash mismatch -> HTTP 400)',
    sigFailReason: 'HMAC signature mismatch (HTTP 401)',
    emptyBodyRule: 'Empty body verified (no hash claim)',
  },
  de: {
    presets: 'Vorlagen:',
    tamper: 'Body manipulieren',
    resign: 'Neu signieren',
    newJti: 'Neue JTI',
    alg: 'Algorithmus',
    hashAlg: 'Body-Hash-Alg',
    kid: 'Key ID (kid)',
    event: 'Webhook Event',
    issuer: 'Issuer (iss)',
    audience: 'Audience (aud)',
    jti: 'Token ID (jti)',
    secret: 'HMAC Secret Key',
    body: 'HTTP POST Request Body',
    bodyEmptyHint: 'Leerer Body: webhook.hash MUSS laut Draft-03 fehlen.',
    encodedToken: 'Kodierter Secure Webhook Token (SWT)',
    copyToken: 'Token kopieren',
    copied: 'Kopiert!',
    copyCurl: 'cURL kopieren',
    validTitle: 'Gültiger SWT — Signatur & Body-Hash verifiziert',
    invalidTitle: 'Verifizierung fehlgeschlagen',
    sigCheck: 'Signatur',
    typCheck: 'typ: "SWT"',
    hashCheck: 'Body-Hash',
    claimsCheck: 'Claims',
    pass: 'OK',
    fail: 'FEHLER',
    decodedHeader: 'Dekodierter Header',
    decodedPayload: 'Dekodierter Payload',
    tamperReason: 'Body wurde nach Signierung verändert (webhook.hash stimmt nicht überein -> HTTP 400)',
    sigFailReason: 'HMAC-Signatur ungültig (HTTP 401)',
    emptyBodyRule: 'Leerer Body verifiziert (kein Hash-Claim)',
  },
} as const;

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeJsonBase64Url(obj: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  return base64UrlEncode(bytes);
}

function generateUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return '550e8400-e29b-41d4-a716-446655440000';
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function subtleHashName(alg: HashAlg): 'SHA-256' | 'SHA-384' | 'SHA-512' {
  switch (alg) {
    case 'sha-384':
      return 'SHA-384';
    case 'sha-512':
      return 'SHA-512';
    default:
      return 'SHA-256';
  }
}

function subtleHmacName(alg: Alg): 'SHA-256' | 'SHA-384' | 'SHA-512' {
  switch (alg) {
    case 'HS384':
      return 'SHA-384';
    case 'HS512':
      return 'SHA-512';
    default:
      return 'SHA-256';
  }
}

async function computeBodyHash(alg: HashAlg, body: string): Promise<string> {
  const data = new TextEncoder().encode(body);
  const digest = await crypto.subtle.digest(subtleHashName(alg), data);
  return `${alg}:${toHex(digest)}`;
}

async function signHmac(alg: Alg, signingInput: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: subtleHmacName(alg) },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  return base64UrlEncode(new Uint8Array(sig));
}

export default function SWTPlayground({ locale = 'en' }: Props) {
  const t = TEXT[locale];
  const [activePreset, setActivePreset] = useState<string>('agent');
  const [alg, setAlg] = useState<Alg>('HS256');
  const [hashAlg, setHashAlg] = useState<HashAlg>('sha-256');
  const [kid, setKid] = useState<string>('key-2026-q4');
  const [event, setEvent] = useState<string>(PRESETS[0].event);
  const [iss, setIss] = useState<string>(PRESETS[0].iss);
  const [aud, setAud] = useState<string>(PRESETS[0].aud);
  const [jti, setJti] = useState<string>('550e8400-e29b-41d4-a716-446655440000');
  const [secret, setSecret] = useState<string>('super-secret-256-bit-webhook-key-2026');
  const [body, setBody] = useState<string>(PRESETS[0].body);
  const [signedBodySnapshot, setSignedBodySnapshot] = useState<string>(PRESETS[0].body);
  const [tampered, setTampered] = useState<boolean>(false);

  const [token, setToken] = useState<string>('');
  const [decodedHeader, setDecodedHeader] = useState<Record<string, unknown>>({});
  const [decodedPayload, setDecodedPayload] = useState<Record<string, unknown>>({});
  const [computedBodyHash, setComputedBodyHash] = useState<string>('');
  const [copiedState, setCopiedState] = useState<'none' | 'token' | 'curl'>('none');

  // Generate real UUID on client mount to avoid SSR hydration mismatch
  useEffect(() => {
    setJti(generateUuid());
  }, []);

  // Recompute token whenever inputs change (except when in tamper mode, where body diverges from signedBodySnapshot)
  useEffect(() => {
    let cancelled = false;

    async function buildToken() {
      if (typeof crypto === 'undefined' || !crypto.subtle) return;

      const now = Math.floor(Date.now() / 1000);
      const bodyToSign = tampered ? signedBodySnapshot : body;
      const bodyHash = bodyToSign.length > 0 ? await computeBodyHash(hashAlg, bodyToSign) : undefined;
      const liveBodyHash = body.length > 0 ? await computeBodyHash(hashAlg, body) : '';

      const header: Record<string, unknown> = {
        alg,
        typ: 'SWT',
      };
      if (kid.trim()) {
        header.kid = kid.trim();
      }

      const webhookClaim: Record<string, unknown> = {
        event: event || 'webhook.event',
        retry_count: 0,
      };
      if (bodyHash) {
        webhookClaim.hash = bodyHash;
      }

      const payload: Record<string, unknown> = {
        webhook: webhookClaim,
        iss,
        aud,
        iat: now,
        nbf: now,
        exp: now + 900,
        jti,
      };

      const signingInput = `${encodeJsonBase64Url(header)}.${encodeJsonBase64Url(payload)}`;
      const signature = await signHmac(alg, signingInput, secret || ' ');

      if (!cancelled) {
        setToken(`${signingInput}.${signature}`);
        setDecodedHeader(header);
        setDecodedPayload(payload);
        setComputedBodyHash(liveBodyHash);
      }
    }

    buildToken();
    return () => {
      cancelled = true;
    };
  }, [alg, hashAlg, kid, event, iss, aud, jti, secret, body, tampered, signedBodySnapshot]);

  const tokenParts = useMemo(() => {
    const parts = token.split('.');
    return {
      header: parts[0] || '',
      payload: parts[1] || '',
      signature: parts[2] || '',
    };
  }, [token]);

  const verification = useMemo(() => {
    const webhook = (decodedPayload.webhook as Record<string, unknown> | undefined) || {};
    const tokenHash = typeof webhook.hash === 'string' ? webhook.hash : '';
    const hasSecret = secret.length > 0;

    let hashOk = false;
    let hashMessage = '';

    if (body.length === 0) {
      hashOk = !tokenHash;
      hashMessage = hashOk ? t.emptyBodyRule : t.tamperReason;
    } else {
      hashOk = Boolean(tokenHash && tokenHash === computedBodyHash);
      hashMessage = hashOk ? `${computedBodyHash.slice(0, 24)}...` : t.tamperReason;
    }

    const claimsOk = Boolean(decodedPayload.iss && decodedPayload.aud && decodedPayload.jti && webhook.event);
    const sigOk = hasSecret && tokenParts.signature.length > 0;
    const allOk = sigOk && hashOk && claimsOk;

    return {
      allOk,
      sigOk,
      hashOk,
      claimsOk,
      hashMessage,
      errorReason: !sigOk ? t.sigFailReason : !hashOk ? t.tamperReason : '',
    };
  }, [decodedPayload, body, computedBodyHash, secret, tokenParts.signature, t]);

  function applyPreset(preset: Preset) {
    setActivePreset(preset.id);
    setEvent(preset.event);
    setIss(preset.iss);
    setAud(preset.aud);
    setBody(preset.body);
    setSignedBodySnapshot(preset.body);
    setTampered(false);
    setJti(generateUuid());
  }

  function handleTamper() {
    if (!tampered) {
      setSignedBodySnapshot(body);
      setTampered(true);
    }
    if (body.length === 0) {
      setBody('{"injected": true}');
    } else if (body.includes('0.99')) {
      setBody(body.replace('0.99', '0.01'));
    } else if (body.includes('149')) {
      setBody(body.replace('149', '9999'));
    } else {
      setBody(`${body} `);
    }
  }

  function handleResign() {
    setSignedBodySnapshot(body);
    setTampered(false);
    setJti(generateUuid());
  }

  async function copyText(kind: 'token' | 'curl') {
    const content =
      kind === 'token'
        ? token
        : `curl -X POST ${aud || 'https://api.example.com/webhooks'} \\\n  -H "Authorization: Bearer ${token}" \\\n  -H "Content-Type: application/json"${
            body ? ` \\\n  -d '${body.replace(/\n\s*/g, ' ')}'` : ''
          }`;
    try {
      await navigator.clipboard.writeText(content);
      setCopiedState(kind);
      setTimeout(() => setCopiedState('none'), 1800);
    } catch {
      // Clipboard API unavailable
    }
  }

  return (
    <div className="swt-pg">
      <div className="swt-pg-toolbar">
        <div className="swt-pg-presets">
          <span className="swt-pg-label">{t.presets}</span>
          {PRESETS.map((p) => (
            <button
              key={p.id}
              type="button"
              className={`swt-pg-btn ${activePreset === p.id ? 'swt-pg-btn--active' : ''}`}
              onClick={() => applyPreset(p)}
            >
              {locale === 'de' ? p.labelDe : p.labelEn}
            </button>
          ))}
        </div>
        <div className="swt-pg-actions">
          <button type="button" className="swt-pg-btn swt-pg-btn--danger" onClick={handleTamper}>
            ⚡ {t.tamper}
          </button>
          <button type="button" className="swt-pg-btn swt-pg-btn--primary" onClick={handleResign}>
            ↻ {t.resign}
          </button>
        </div>
      </div>

      <div className="swt-pg-grid">
        {/* Left Column: Request & Claims */}
        <div className="swt-pg-col">
          <div className="swt-pg-row">
            <div className="swt-pg-field">
              <label htmlFor="swt-alg">{t.alg}</label>
              <select
                id="swt-alg"
                className="swt-pg-select"
                value={alg}
                onChange={(e) => setAlg(e.target.value as Alg)}
              >
                <option value="HS256">HS256 (HMAC-SHA256)</option>
                <option value="HS384">HS384 (HMAC-SHA384)</option>
                <option value="HS512">HS512 (HMAC-SHA512)</option>
              </select>
            </div>
            <div className="swt-pg-field">
              <label htmlFor="swt-hash-alg">{t.hashAlg}</label>
              <select
                id="swt-hash-alg"
                className="swt-pg-select"
                value={hashAlg}
                onChange={(e) => setHashAlg(e.target.value as HashAlg)}
              >
                <option value="sha-256">sha-256</option>
                <option value="sha-384">sha-384</option>
                <option value="sha-512">sha-512</option>
              </select>
            </div>
          </div>

          <div className="swt-pg-row">
            <div className="swt-pg-field">
              <label htmlFor="swt-event">{t.event}</label>
              <input
                id="swt-event"
                className="swt-pg-input"
                value={event}
                onChange={(e) => setEvent(e.target.value)}
              />
            </div>
            <div className="swt-pg-field">
              <label htmlFor="swt-kid">{t.kid}</label>
              <input
                id="swt-kid"
                className="swt-pg-input"
                value={kid}
                onChange={(e) => setKid(e.target.value)}
              />
            </div>
          </div>

          <div className="swt-pg-row">
            <div className="swt-pg-field">
              <label htmlFor="swt-iss">{t.issuer}</label>
              <input
                id="swt-iss"
                className="swt-pg-input"
                value={iss}
                onChange={(e) => setIss(e.target.value)}
              />
            </div>
            <div className="swt-pg-field">
              <label htmlFor="swt-aud">{t.audience}</label>
              <input
                id="swt-aud"
                className="swt-pg-input"
                value={aud}
                onChange={(e) => setAud(e.target.value)}
              />
            </div>
          </div>

          <div className="swt-pg-field">
            <div className="swt-pg-field-header">
              <label htmlFor="swt-jti">{t.jti}</label>
              <button
                type="button"
                className="swt-pg-btn"
                onClick={() => setJti(generateUuid())}
              >
                {t.newJti}
              </button>
            </div>
            <input
              id="swt-jti"
              className="swt-pg-input"
              value={jti}
              onChange={(e) => setJti(e.target.value)}
            />
          </div>

          <div className="swt-pg-field">
            <label htmlFor="swt-secret">{t.secret}</label>
            <input
              id="swt-secret"
              className="swt-pg-input"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </div>

          <div className="swt-pg-field">
            <label htmlFor="swt-body">{t.body}</label>
            <textarea
              id="swt-body"
              className="swt-pg-textarea"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder={t.bodyEmptyHint}
            />
          </div>
        </div>

        {/* Right Column: Encoded Token & Verification */}
        <div className="swt-pg-col">
          <div className={`swt-pg-status ${verification.allOk ? 'swt-pg-status--ok' : 'swt-pg-status--err'}`}>
            <div className="swt-pg-status-title">
              <span>{verification.allOk ? '✓' : '✕'}</span>
              <span>{verification.allOk ? t.validTitle : t.invalidTitle}</span>
            </div>
            {verification.errorReason && <div>{verification.errorReason}</div>}
            <div className="swt-pg-checks">
              <span className="swt-pg-check-pill">
                {t.typCheck}: {t.pass}
              </span>
              <span className="swt-pg-check-pill">
                {t.sigCheck}: {verification.sigOk ? t.pass : t.fail}
              </span>
              <span className="swt-pg-check-pill">
                {t.hashCheck}: {verification.hashOk ? t.pass : t.fail}
              </span>
              <span className="swt-pg-check-pill">
                {t.claimsCheck}: {verification.claimsOk ? t.pass : t.fail}
              </span>
            </div>
          </div>

          <div className="swt-pg-field">
            <div className="swt-pg-field-header">
              <label>{t.encodedToken}</label>
              <div className="swt-pg-actions">
                <button type="button" className="swt-pg-btn" onClick={() => copyText('token')}>
                  {copiedState === 'token' ? t.copied : t.copyToken}
                </button>
                <button type="button" className="swt-pg-btn" onClick={() => copyText('curl')}>
                  {copiedState === 'curl' ? t.copied : t.copyCurl}
                </button>
              </div>
            </div>
            <div className="swt-pg-token-box">
              <span className="swt-tok-header">{tokenParts.header}</span>
              <span className="swt-tok-dot">.</span>
              <span className="swt-tok-payload">{tokenParts.payload}</span>
              <span className="swt-tok-dot">.</span>
              <span className="swt-tok-sig">{tokenParts.signature}</span>
            </div>
          </div>

          <div className="swt-pg-field">
            <label>{t.decodedHeader}</label>
            <pre className="swt-pg-pre">{JSON.stringify(decodedHeader, null, 2)}</pre>
          </div>

          <div className="swt-pg-field">
            <label>{t.decodedPayload}</label>
            <pre className="swt-pg-pre">{JSON.stringify(decodedPayload, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
