import React, { useCallback, useEffect, useMemo, useState } from 'react';
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
    autoSign: 'Auto-sign',
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
    tamperReason: 'Body does not match signed webhook.hash (HTTP 400). Click "Re-sign Token" to update.',
    sigFailReason: 'HMAC signature verification failed with current secret (HTTP 401).',
    claimsFailReason: 'Input claims (jti, iss, aud, or event) differ from the signed token. Click "Re-sign Token" to update.',
    emptyBodyRule: 'Empty body verified (no hash claim)',
  },
  de: {
    presets: 'Vorlagen:',
    autoSign: 'Auto-Sign',
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
    tamperReason: 'Body stimmt nicht mit signiertem webhook.hash überein (HTTP 400). Klicke auf „Neu signieren“.',
    sigFailReason: 'HMAC-Signaturprüfung mit aktuellem Secret fehlgeschlagen (HTTP 401).',
    claimsFailReason: 'Eingabe-Claims (jti, iss, aud oder event) weichen vom signierten Token ab. Klicke auf „Neu signieren“.',
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

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

function subtleHmacName(alg: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
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
    enc.encode(secret || ' '),
    { name: 'HMAC', hash: subtleHmacName(alg) },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  return base64UrlEncode(new Uint8Array(sig));
}

async function verifyHmac(token: string, secret: string): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 3 || !secret) return false;
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))) as { alg?: string };
    const alg = header.alg || 'HS256';
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: subtleHmacName(alg) },
      false,
      ['verify']
    );
    const sigBytes = base64UrlDecode(parts[2]);
    const signingInput = enc.encode(`${parts[0]}.${parts[1]}`);
    return await crypto.subtle.verify('HMAC', key, sigBytes as BufferSource, signingInput);
  } catch {
    return false;
  }
}

export default function SWTPlayground({ locale = 'en' }: Props) {
  const t = TEXT[locale];
  const [activePreset, setActivePreset] = useState<string>('agent');
  const [autoSign, setAutoSign] = useState<boolean>(false);
  const [alg, setAlg] = useState<Alg>('HS256');
  const [hashAlg, setHashAlg] = useState<HashAlg>('sha-256');
  const [kid, setKid] = useState<string>('key-2026-q4');
  const [event, setEvent] = useState<string>(PRESETS[0].event);
  const [iss, setIss] = useState<string>(PRESETS[0].iss);
  const [aud, setAud] = useState<string>(PRESETS[0].aud);
  const [jti, setJti] = useState<string>('550e8400-e29b-41d4-a716-446655440000');
  const [secret, setSecret] = useState<string>('super-secret-256-bit-webhook-key-2026');
  const [body, setBody] = useState<string>(PRESETS[0].body);

  const [token, setToken] = useState<string>('');
  const [decodedHeader, setDecodedHeader] = useState<Record<string, unknown>>({});
  const [decodedPayload, setDecodedPayload] = useState<Record<string, unknown>>({});
  const [sigValid, setSigValid] = useState<boolean>(true);
  const [computedBodyHash, setComputedBodyHash] = useState<string>('');
  const [copiedState, setCopiedState] = useState<'none' | 'token' | 'curl'>('none');

  const signCurrentToken = useCallback(
    async (params: {
      alg: Alg;
      hashAlg: HashAlg;
      kid: string;
      event: string;
      iss: string;
      aud: string;
      jti: string;
      secret: string;
      body: string;
    }) => {
      if (typeof crypto === 'undefined' || !crypto.subtle) return;
      const now = Math.floor(Date.now() / 1000);
      const bodyHash = params.body.length > 0 ? await computeBodyHash(params.hashAlg, params.body) : undefined;

      const header: Record<string, unknown> = {
        alg: params.alg,
        typ: 'SWT',
      };
      if (params.kid.trim()) {
        header.kid = params.kid.trim();
      }

      const webhookClaim: Record<string, unknown> = {
        event: params.event || 'webhook.event',
        retry_count: 0,
      };
      if (bodyHash) {
        webhookClaim.hash = bodyHash;
      }

      const payload: Record<string, unknown> = {
        webhook: webhookClaim,
        iss: params.iss,
        aud: params.aud,
        iat: now,
        nbf: now,
        exp: now + 900,
        jti: params.jti,
      };

      const signingInput = `${encodeJsonBase64Url(header)}.${encodeJsonBase64Url(payload)}`;
      const signature = await signHmac(params.alg, signingInput, params.secret);

      setToken(`${signingInput}.${signature}`);
      setDecodedHeader(header);
      setDecodedPayload(payload);
    },
    []
  );

  // Initial mount: generate UUID and sign initial token
  useEffect(() => {
    const initialJti = generateUuid();
    setJti(initialJti);
    signCurrentToken({
      alg,
      hashAlg,
      kid,
      event,
      iss,
      aud,
      jti: initialJti,
      secret,
      body,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // If autoSign is enabled, re-sign automatically when inputs change
  useEffect(() => {
    if (!autoSign) return;
    signCurrentToken({ alg, hashAlg, kid, event, iss, aud, jti, secret, body });
  }, [autoSign, alg, hashAlg, kid, event, iss, aud, jti, secret, body, signCurrentToken]);

  // Real receiver verification whenever token, secret, or body changes
  useEffect(() => {
    let cancelled = false;
    async function runVerification() {
      if (typeof crypto === 'undefined' || !crypto.subtle || !token) return;
      const webhook = (decodedPayload.webhook as Record<string, unknown> | undefined) || {};
      const tokenHash = typeof webhook.hash === 'string' ? webhook.hash : '';
      const tokenHashAlg = (tokenHash.split(':')[0] as HashAlg) || hashAlg;
      const validHashAlg: HashAlg =
        tokenHashAlg === 'sha-384' || tokenHashAlg === 'sha-512' ? tokenHashAlg : 'sha-256';

      const [isSigOk, liveHash] = await Promise.all([
        verifyHmac(token, secret),
        body.length > 0 ? computeBodyHash(validHashAlg, body) : Promise.resolve(''),
      ]);

      if (!cancelled) {
        setSigValid(isSigOk);
        setComputedBodyHash(liveHash);
      }
    }
    runVerification();
    return () => {
      cancelled = true;
    };
  }, [token, secret, body, decodedPayload, hashAlg]);

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

    let hashOk = false;
    if (body.length === 0) {
      hashOk = !tokenHash;
    } else {
      hashOk = Boolean(tokenHash && tokenHash === computedBodyHash);
    }

    const claimsMatchInput =
      decodedPayload.jti === jti &&
      decodedPayload.iss === iss &&
      decodedPayload.aud === aud &&
      webhook.event === (event || 'webhook.event');

    const claimsOk = Boolean(
      decodedPayload.iss && decodedPayload.aud && decodedPayload.jti && webhook.event && claimsMatchInput
    );
    const typOk = decodedHeader.typ === 'SWT';
    const allOk = sigValid && hashOk && claimsOk && typOk;

    const reasons: string[] = [];
    if (!sigValid) reasons.push(t.sigFailReason);
    if (!hashOk) reasons.push(t.tamperReason);
    if (!claimsOk) reasons.push(t.claimsFailReason);

    return {
      allOk,
      sigOk: sigValid,
      hashOk,
      claimsOk,
      typOk,
      reasons,
    };
  }, [decodedHeader, decodedPayload, body, computedBodyHash, sigValid, jti, iss, aud, event, t]);

  function applyPreset(preset: Preset) {
    const nextJti = generateUuid();
    setActivePreset(preset.id);
    setEvent(preset.event);
    setIss(preset.iss);
    setAud(preset.aud);
    setBody(preset.body);
    setJti(nextJti);
    signCurrentToken({
      alg,
      hashAlg,
      kid,
      event: preset.event,
      iss: preset.iss,
      aud: preset.aud,
      jti: nextJti,
      secret,
      body: preset.body,
    });
  }

  function handleTamper() {
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
    signCurrentToken({ alg, hashAlg, kid, event, iss, aud, jti, secret, body });
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
    <div className="swt-pg not-content">
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
          <label className="swt-pg-toggle">
            <input
              type="checkbox"
              checked={autoSign}
              onChange={(e) => setAutoSign(e.target.checked)}
            />
            <span>{t.autoSign}</span>
          </label>
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
            {verification.reasons.map((reason, idx) => (
              <div key={idx}>{reason}</div>
            ))}
            <div className="swt-pg-checks">
              <span className="swt-pg-check-pill">
                {t.typCheck}: {verification.typOk ? t.pass : t.fail}
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
