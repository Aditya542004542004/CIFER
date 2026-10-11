"""
CIFER v4 — Core Cryptographic Module
Implements:
  - AES-256-GCM AEAD with dual-AAD context binding (blob_aad & wrap_aad)
  - Envelope Encryption with ephemeral DEKs wrapped under KEK_MASTER
  - RFC 9106 Argon2id Password Hashing with legacy SHA-256 migration
  - Server-Keyed HMAC-SHA-256 OTP engine
  - Length-Prefixed Canonical Encoding (LenEnc)
  - Format-Compliant Polyglot Carrier (JPEG + marker + ciphertext blob)
"""

import os
import hmac
import hashlib
import secrets
import unicodedata
import uuid
from typing import Tuple, List, Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import argon2

# ─────────────────────────────────────────────
#  1. Length-Prefixed Canonical Encoding (LenEnc)
# ─────────────────────────────────────────────
def len_enc(data: Union[bytes, str, int]) -> bytes:
    """Encodes data with a 4-byte big-endian length prefix."""
    if isinstance(data, int):
        data = str(data).encode("utf-8")
    elif isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return len(data).to_bytes(4, byteorder="big") + data


def canonical_recipients_str(recipients: Union[List[str], str]) -> str:
    """Normalizes, lowercases, de-duplicates, and sorts recipient emails."""
    if isinstance(recipients, str):
        import json
        try:
            parsed = json.loads(recipients)
            if isinstance(parsed, list):
                recipients = parsed
            else:
                recipients = [recipients]
        except Exception:
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]

    cleaned = sorted(
        set(
            unicodedata.normalize("NFKC", r).strip().lower()
            for r in recipients
            if r and r.strip()
        )
    )
    return ",".join(cleaned)


# ─────────────────────────────────────────────
#  2. Dual AAD Constructors
# ─────────────────────────────────────────────
def build_blob_aad(version: Union[int, str], file_uuid: str, owner_id: str, version_no: Union[int, str]) -> bytes:
    """
    Binds immutable identity:
    LenEnc(Ver) || LenEnc(FileUUID) || LenEnc(OwnerID) || LenEnc(VersionNo)
    """
    return (
        len_enc(version)
        + len_enc(file_uuid)
        + len_enc(owner_id)
        + len_enc(version_no)
    )


def build_wrap_aad(
    version: Union[int, str],
    file_uuid: str,
    version_no: Union[int, str],
    filename: str,
    recipients: Union[List[str], str],
    token_hash: str
) -> bytes:
    """
    Binds mutable context:
    LenEnc(Ver) || LenEnc(FileUUID) || LenEnc(VersionNo) || LenEnc(Filename) || LenEnc(Recipients) || LenEnc(H_tok)
    """
    canon_recips = canonical_recipients_str(recipients)
    return (
        len_enc(version)
        + len_enc(file_uuid)
        + len_enc(version_no)
        + len_enc(filename)
        + len_enc(canon_recips)
        + len_enc(token_hash)
    )


# ─────────────────────────────────────────────
#  3. Envelope Encryption & Decryption
# ─────────────────────────────────────────────
class CiferCryptoResult:
    def __init__(
        self,
        file_uuid: str,
        blob_bytes: bytes,
        wrapped_dek: bytes,
        wrap_iv: bytes,
        token_hash: str,
        bearer_token: str,
        blob_fingerprint: str,
        kek_id: str,
        version: int,
        version_no: int
    ):
        self.file_uuid = file_uuid
        self.blob_bytes = blob_bytes
        self.wrapped_dek = wrapped_dek
        self.wrap_iv = wrap_iv
        self.token_hash = token_hash
        self.bearer_token = bearer_token
        self.blob_fingerprint = blob_fingerprint
        self.kek_id = kek_id
        self.version = version
        self.version_no = version_no

    def to_tuple(self):
        return (
            self.blob_bytes,
            self.wrapped_dek,
            self.wrap_iv,
            self.token_hash,
            self.bearer_token,
            self.blob_fingerprint
        )


def encrypt_file(
    file_bytes: bytes,
    filename: str,
    owner_id: str,
    recipients: Union[List[str], str],
    kek_bytes: bytes,
    kek_id: str,
    version: int = 4,
    version_no: int = 1,
    file_uuid: Optional[str] = None
) -> CiferCryptoResult:
    """
    Encrypts plaintext via AES-256-GCM under an ephemeral DEK,
    and wraps the DEK under KEK_MASTER with context-bound dual-AAD.
    """
    if file_uuid is None:
        file_uuid = str(uuid.uuid4())

    # 1. Ephemeral 256-bit DEK & 96-bit IV
    k_dek = os.urandom(32)
    iv_blob = os.urandom(12)

    # 2. Encrypt plaintext with AES-GCM and AAD_blob
    blob_aad = build_blob_aad(version, file_uuid, owner_id, version_no)
    aesgcm_dek = AESGCM(k_dek)
    # encrypt returns ciphertext + 16-byte auth tag
    ct_and_tag = aesgcm_dek.encrypt(iv_blob, file_bytes, blob_aad)
    blob_bytes = iv_blob + ct_and_tag  # IV (12B) + Ciphertext + Tag (16B)

    # 3. Generate random 96-bit wrap IV & 256-bit bearer token
    wrap_iv = os.urandom(12)
    bearer_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()

    # 4. Wrap DEK under KEK_MASTER with AAD_wrap
    wrap_aad = build_wrap_aad(version, file_uuid, version_no, filename, recipients, token_hash)
    aesgcm_kek = AESGCM(kek_bytes)
    wrapped_dek = aesgcm_kek.encrypt(wrap_iv, k_dek, wrap_aad)

    # 5. Compute SHA-256 fingerprint of the ciphertext blob
    blob_fingerprint = hashlib.sha256(blob_bytes).hexdigest()

    return CiferCryptoResult(
        file_uuid=file_uuid,
        blob_bytes=blob_bytes,
        wrapped_dek=wrapped_dek,
        wrap_iv=wrap_iv,
        token_hash=token_hash,
        bearer_token=bearer_token,
        blob_fingerprint=blob_fingerprint,
        kek_id=kek_id,
        version=version,
        version_no=version_no
    )


def unwrap_dek(wrapped_dek: bytes, wrap_iv: bytes, kek_bytes: bytes, wrap_aad: bytes) -> bytes:
    """
    Unwraps K_DEK using AESGCM(KEK). Raises InvalidTag on verification failure.
    """
    aesgcm_kek = AESGCM(kek_bytes)
    return aesgcm_kek.decrypt(wrap_iv, wrapped_dek, wrap_aad)


def decrypt_file(blob_bytes: bytes, dek: bytes, blob_aad: bytes) -> bytes:
    """
    Decrypts the ciphertext blob using AESGCM(DEK) and blob_aad.
    blob_bytes format: IV (12B) + Ciphertext + Tag (16B).
    """
    if len(blob_bytes) < 28:
        raise ValueError("Ciphertext blob is too short (must be at least 28 bytes).")
    iv = blob_bytes[:12]
    ct_and_tag = blob_bytes[12:]
    aesgcm = AESGCM(dek)
    return aesgcm.decrypt(iv, ct_and_tag, blob_aad)


# ─────────────────────────────────────────────
#  4. Argon2id Credential Engine
# ─────────────────────────────────────────────
# RFC 9106 recommended parameters: t=3, m=64MB (65536 KiB), p=4, salt=16 bytes
_password_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID
)


def hash_password(password: str) -> str:
    """Hashes a password using Argon2id with RFC 9106 parameters."""
    return _password_hasher.hash(password)


def verify_password(hash_str: str, password: str) -> Tuple[bool, bool]:
    """
    Verifies a password. Supports transparent auto-migration from legacy SHA-256.
    Returns: (is_valid: bool, needs_rehash: bool)
    """
    if not hash_str or not password:
        return False, False

    # Check if Argon2id format
    if hash_str.startswith("$argon2"):
        try:
            _password_hasher.verify(hash_str, password)
            needs_rehash = _password_hasher.check_needs_rehash(hash_str)
            return True, needs_rehash
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            return False, False
        except Exception:
            return False, False

    # Check for legacy unsalted SHA-256 hex string (64 chars)
    if len(hash_str) == 64:
        cand_hash = hashlib.sha256(password.encode("utf-8")).hexdigest().lower()
        if hmac.compare_digest(cand_hash, hash_str.lower()):
            # Valid legacy password -> must rehash to Argon2id
            return True, True

    return False, False


# ─────────────────────────────────────────────
#  5. Server-Keyed HMAC OTP Engine
# ─────────────────────────────────────────────
def generate_otp_digest(user_id: str, purpose: str, challenge_id: str, code_str: str, hmac_key: bytes) -> str:
    """
    Computes server-keyed HMAC-SHA256:
    HMAC-SHA256_K_HMAC(LenEnc(user_id) || LenEnc(purpose) || LenEnc(challenge_id) || LenEnc(code_str))
    """
    payload = (
        len_enc(user_id)
        + len_enc(purpose)
        + len_enc(challenge_id)
        + len_enc(code_str)
    )
    return hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()


def verify_otp(stored_digest: str, candidate_digest: str) -> bool:
    """Constant-time verification of OTP digests."""
    return hmac.compare_digest(stored_digest, candidate_digest)


# ─────────────────────────────────────────────
#  6. Format-Compliant Polyglot Carrier
# ─────────────────────────────────────────────
CARRIER_MARKER = b"[CIFER_DATA]"


def bundle_jpeg(cover_path: str, blob_bytes: bytes) -> bytes:
    """
    Bundles the ciphertext blob after the JPEG cover image and sentinel marker:
    F_bundle = B_JPEG || b'[CIFER_DATA]' || IV_12 || C || T_16.
    Note: The bearer capability token is intentionally NOT stored inside the JPEG.
    """
    with open(cover_path, "rb") as f:
        cover_bytes = f.read()
    return cover_bytes + CARRIER_MARKER + blob_bytes


def extract_from_jpeg(carrier_bytes: bytes) -> bytes:
    """
    Extracts the raw encrypted blob bytes from the carrier image by locating the marker.
    """
    idx = carrier_bytes.find(CARRIER_MARKER)
    if idx == -1:
        raise ValueError("This image does not contain CIFER encrypted data.")
    return carrier_bytes[idx + len(CARRIER_MARKER):]
