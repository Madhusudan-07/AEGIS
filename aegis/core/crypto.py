"""Cryptographic wrappers — VETTED LIBRARIES ONLY (spec §5).

Nothing here implements a primitive. Each function is a thin, safe-by-default wrapper:

* Password hashing  -> argon2-cffi  (Argon2id)            ASVS V2.4 / OWASP A07
* Token sign/verify -> PyJWT        (HS256 default; alg pinned, ``none`` rejected) ASVS V3 / A07
* Field encryption  -> cryptography (AES-256-GCM, AEAD)   ASVS V6 / A02
* Key derivation    -> cryptography (HKDF-SHA256)         ASVS V6
* Random tokens/IDs -> ``secrets``  (CSPRNG)              ASVS V2.3 / A02

FORBIDDEN here and verified absent: MD5/SHA1 for passwords, custom token formats,
``alg:none``, predictable IDs, hand-rolled crypto.
"""
from __future__ import annotations

import base64
import hmac
import os
import secrets as _secrets
import time
import uuid

import jwt  # PyJWT
from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import AuthenticationError, CryptoError

# ---------------------------------------------------------------------------
# CSPRNG helpers
# ---------------------------------------------------------------------------

def random_token(nbytes: int = 32) -> str:
    """URL-safe CSPRNG token. Use for session ids, CSRF tokens, API keys, nonces."""
    return _secrets.token_urlsafe(nbytes)


def random_id() -> str:
    """Unpredictable, collision-resistant id (UUIDv4 — never sequential)."""
    return uuid.uuid4().hex


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """Timing-safe equality (wraps ``hmac.compare_digest``)."""
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Password hashing — Argon2id
# ---------------------------------------------------------------------------
# Tuned defaults from argon2-cffi (OWASP-recommended ballpark). Override via ctor.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    if not password:
        raise CryptoError("empty password")
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time verify. Returns False on mismatch (never raises on bad password)."""
    try:
        return _hasher.verify(stored_hash, password)
    except (argon2_exceptions.VerifyMismatchError, argon2_exceptions.InvalidHashError, argon2_exceptions.VerificationError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """True if params changed since hashing — caller should re-hash on next login."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except argon2_exceptions.InvalidHashError:
        return True


# ---------------------------------------------------------------------------
# HMAC (for CSRF double-submit, signed cookies)
# ---------------------------------------------------------------------------

def hmac_sign(secret: str, message: str) -> str:
    import hashlib
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def hmac_verify(secret: str, message: str, signature: str) -> bool:
    return constant_time_compare(hmac_sign(secret, message), signature)


# ---------------------------------------------------------------------------
# JWT tokens — PyJWT
# ---------------------------------------------------------------------------
class TokenService:
    """Issue and verify JWTs with safe defaults.

    * Algorithm is **pinned** and ``none`` is rejected unconditionally.
    * Verification requires ``exp``/``iat``/``sub`` and checks ``iss``/``aud``.
    * Asymmetric algs verify with ``public_key`` (for integrating an external IdP).
    """

    _ASYMMETRIC = ("RS", "ES", "PS", "Ed")

    def __init__(self, secret: str, *, algorithm: str = "HS256", issuer: str = "aegis",
                 audience: str = "aegis", leeway: int = 10, public_key: str = ""):
        if algorithm.lower() == "none":
            raise CryptoError("JWT 'alg: none' is forbidden")
        self.secret = secret
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.public_key = public_key

    @property
    def _is_asymmetric(self) -> bool:
        return self.algorithm.startswith(self._ASYMMETRIC)

    def _verify_key(self) -> str:
        if self._is_asymmetric:
            if not self.public_key:
                raise CryptoError(f"{self.algorithm} requires a configured jwt_public_key")
            return self.public_key
        return self.secret

    def issue(self, subject: str, *, ttl: int, roles=(), token_type: str = "access", extra: dict | None = None) -> str:
        if self._is_asymmetric:
            # Signing with a private key is the IdP's job; AEGIS issues symmetric tokens.
            raise CryptoError("AEGIS issues HMAC tokens only; asymmetric algs are verify-only")
        now = int(time.time())
        payload = {
            "sub": subject,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "iss": self.issuer,
            "aud": self.audience,
            "type": token_type,
            "roles": list(roles),
            "jti": random_id(),  # enables replay/revocation tracking
        }
        if extra:
            payload.update(extra)
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify(self, token: str, *, expected_type: str | None = None) -> dict:
        try:
            payload = jwt.decode(
                token,
                self._verify_key(),
                algorithms=[self.algorithm],  # explicit allow-list -> 'none' impossible
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "sub"], "verify_signature": True},
            )
        except jwt.PyJWTError as exc:
            # Generic to the caller; detail is internal only.
            raise AuthenticationError(f"jwt verify failed: {exc.__class__.__name__}") from exc
        if expected_type is not None and payload.get("type") != expected_type:
            raise AuthenticationError(f"unexpected token type: {payload.get('type')!r}")
        return payload


# ---------------------------------------------------------------------------
# Field-level encryption — AES-256-GCM (AEAD)
# ---------------------------------------------------------------------------
_PREFIX = "aegis1:"  # versioned envelope -> crypto agility (rotate algs later)


def generate_field_key() -> str:
    """Generate a fresh AES-256 key as a urlsafe-base64 string (store in secret mgr)."""
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()


def load_key(material: str) -> bytes:
    """Accept urlsafe-b64(32B), hex(64), or raw 32B; reject anything that isn't 256-bit."""
    if not material:
        raise CryptoError("empty encryption key")
    for decoder in (lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
                    bytes.fromhex,
                    lambda s: s.encode()):
        try:
            key = decoder(material)
        except Exception:  # nosec B112 - deliberately trying multiple key encodings
            continue
        if len(key) == 32:
            return key
    raise CryptoError("encryption key must decode to exactly 32 bytes (AES-256)")


def derive_key(master: bytes, info: bytes, *, length: int = 32, salt: bytes = b"") -> bytes:
    """HKDF-SHA256 sub-key derivation (per-purpose keys from one master)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(master)


class FieldCipher:
    """Authenticated encryption for individual sensitive fields (PII at rest)."""

    def __init__(self, key_material: str):
        self._key = load_key(key_material)

    def encrypt(self, plaintext: str | bytes, *, aad: bytes = b"") -> str:
        data = plaintext.encode() if isinstance(plaintext, str) else plaintext
        nonce = os.urandom(12)  # 96-bit GCM nonce, fresh per call
        ct = AESGCM(self._key).encrypt(nonce, data, aad)
        return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str, *, aad: bytes = b"") -> bytes:
        if not isinstance(token, str) or not token.startswith(_PREFIX):
            raise CryptoError("unrecognized ciphertext envelope")
        try:
            raw = base64.urlsafe_b64decode(token[len(_PREFIX):])
            nonce, ct = raw[:12], raw[12:]
            return AESGCM(self._key).decrypt(nonce, ct, aad)
        except CryptoError:
            raise
        except Exception as exc:  # bad base64, short input, InvalidTag, wrong key...
            # Any malformed/tampered input -> fail closed, no detail leaked.
            raise CryptoError("decryption failed (tampered ciphertext or wrong key)") from exc
