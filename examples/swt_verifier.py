from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time

ALLOWED_SIG_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
ALLOWED_HASH_ALGS = {
    "sha-256": hashlib.sha256,
    "sha-384": hashlib.sha384,
    "sha-512": hashlib.sha512,
    "sha3-256": hashlib.sha3_256,
    "sha3-384": hashlib.sha3_384,
    "sha3-512": hashlib.sha3_512,
}
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB


def b64url_decode(segment: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("Malformed base64url segment")
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class AtomicMemoryReplayStore:
    """Thread-safe in-memory replay store for single-process testing ONLY.
    Distributed deployments MUST use atomic Redis SET NX EX or SQL UNIQUE constraint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}

    def reserve(self, scope_key: str, ttl_seconds: int, now_seconds: int) -> bool:
        with self._lock:
            expired = [k for k, exp in self._seen.items() if exp <= now_seconds]
            for k in expired:
                del self._seen[k]
            if scope_key in self._seen:
                return False
            self._seen[scope_key] = now_seconds + ttl_seconds
            return True


def verify_swt_request(
    *,
    scheme: str = "https",
    method: str = "POST",
    authorization: str = "",
    raw_body: bytes = b"",
    key_resolver,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    now_seconds: int | None = None,
    clock_skew_seconds: int = 60,
    allowed_algorithms: set[str] | list[str] | tuple[str, ...] | None = None,
    max_body_bytes: int = MAX_BODY_BYTES,
    replay_store: AtomicMemoryReplayStore | None = None,
) -> tuple[bool, int, dict | str]:
    now = int(time.time()) if now_seconds is None else now_seconds
    sig_allowlist = set(ALLOWED_SIG_ALGS) if allowed_algorithms is None else set(allowed_algorithms)

    if scheme != "https":
        return False, 400, "HTTPS required"
    if method != "POST":
        return False, 405, "Method must be POST"
    if len(raw_body) > max_body_bytes:
        return False, 413, "Body too large"
    if not authorization.startswith("Bearer "):
        return False, 401, "Missing Bearer token"

    token = authorization[len("Bearer ") :].strip()
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return False, 400, "Malformed JWT structure"

    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return False, 400, "Invalid JSON in JWT"

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_SIG_ALGS or alg not in sig_allowlist:
        return False, 401, "Unsupported or disallowed algorithm"
    if header.get("typ") != "SWT":
        return False, 401, "Invalid typ header (must be SWT)"

    kid = header.get("kid")
    if kid is not None and (not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", kid)):
        return False, 400, "Invalid kid format"

    secret = key_resolver(kid)
    if not secret:
        return False, 401, "Unknown verification key"

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, ALLOWED_SIG_ALGS[alg]).digest()
    try:
        actual_sig = b64url_decode(parts[2])
    except Exception:
        return False, 401, "Malformed signature encoding"

    if len(actual_sig) != len(expected_sig) or not hmac.compare_digest(actual_sig, expected_sig):
        return False, 401, "Invalid signature"

    iss = payload.get("iss")
    jti = payload.get("jti")
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    if (
        not isinstance(iss, str)
        or not iss
        or not isinstance(jti, str)
        or not jti
        or not isinstance(exp, (int, float))
        or not isinstance(nbf, (int, float))
        or not isinstance(iat, (int, float))
    ):
        return False, 400, "Missing or invalid standard claims"

    if now >= exp + clock_skew_seconds:
        return False, 401, "Token expired"
    if now < nbf - clock_skew_seconds:
        return False, 401, "Token not yet valid (nbf)"

    if expected_issuer and iss != expected_issuer:
        return False, 403, "Issuer mismatch"
    if expected_audience:
        aud = payload.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        if expected_audience not in aud_list:
            return False, 403, "Audience mismatch"

    wh = payload.get("webhook")
    if not isinstance(wh, dict) or not isinstance(wh.get("event"), str) or not wh["event"]:
        return False, 400, "Missing webhook.event"

    rc = wh.get("retry_count")
    if rc is not None and (isinstance(rc, bool) or not isinstance(rc, int) or rc < 0):
        return False, 400, "Invalid webhook.retry_count"

    if len(raw_body) > 0:
        wh_hash = wh.get("hash")
        if not isinstance(wh_hash, str) or ":" not in wh_hash:
            return False, 400, "Missing or malformed webhook.hash"
        hash_alg, expected_hex = wh_hash.split(":", 1)
        hash_fn = ALLOWED_HASH_ALGS.get(hash_alg)
        if hash_fn is None:
            return False, 400, "Unsupported hash algorithm"
        if not re.fullmatch(r"[0-9a-f]+", expected_hex) or len(expected_hex) % 2 != 0:
            return False, 400, "Malformed hex digest"
        actual_digest = hash_fn(raw_body).digest()
        expected_digest = bytes.fromhex(expected_hex)
        if len(actual_digest) != len(expected_digest) or not hmac.compare_digest(actual_digest, expected_digest):
            return False, 400, "Body hash mismatch"
    elif "hash" in wh:
        return False, 400, "webhook.hash must be absent for empty body"

    if replay_store is not None:
        ttl = max(1, int(exp - now + clock_skew_seconds))
        if not replay_store.reserve(f"{iss}:{jti}", ttl, now):
            return False, 401, "Replay detected (duplicate jti)"

    return True, 200, payload
# Conformance testing is executed via https://github.com/SecureWebhookToken/swt-conformance
