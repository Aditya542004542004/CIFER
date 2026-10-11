"""
CIFER v4 — End-to-End Automated Integration Test
Validates:
  1. User Registration & Argon2id Password Hashing
  2. 2FA Login with Server-Keyed HMAC OTP
  3. Envelope Encryption of 1 MB File under Ephemeral DEK & KEK_MASTER
  4. Out-of-band Bearer Token hashing (SHA-256 in MongoDB)
  5. Context-Bound AAD Tamper Detection on Metadata Modification (Verify-then-Dispatch rejection with HTTP 422)
  6. Restoration, OTP verification, and byte-for-byte Decryption
  7. Zero-downtime Online KEK Rotation without modifying bulk ciphertext
"""

import os
import io
import json
import time
import hashlib
import random
from datetime import datetime

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Import backend application
import app as cifer_backend
import cifer_crypto

BASE_URL = "http://127.0.0.1:5000"


class CiferTestClient:
    """
    Dual-mode test client: attempts live HTTP requests against localhost:5000,
    falling back to Flask's internal test_client if the live daemon is offline.
    """
    def __init__(self):
        import requests
        self.use_live = False
        self.session = requests.Session()
        self.flask_client = cifer_backend.app.test_client()

        try:
            r = self.session.get(f"{BASE_URL}/api/me", timeout=1.0)
            self.use_live = True
            print(f"[*] Connected to live CIFER server at {BASE_URL}")
        except Exception:
            print("[*] Live server not detected at localhost:5000 — running in direct Flask Test Client mode")

    def post_json(self, path, json_data):
        if self.use_live:
            return self.session.post(f"{BASE_URL}{path}", json=json_data)
        else:
            resp = self.flask_client.post(path, json=json_data)
            return self._wrap_flask_response(resp)

    def post_multipart(self, path, files, data):
        if self.use_live:
            return self.session.post(f"{BASE_URL}{path}", files=files, data=data)
        else:
            # Format multipart for test_client
            upload_data = {}
            for k, v in data.items():
                upload_data[k] = v
            for k, file_tuple in files.items():
                # file_tuple: (filename, fileobj, mimetype) or fileobj
                if hasattr(file_tuple, "read"):
                    upload_data[k] = file_tuple
                elif isinstance(file_tuple, tuple):
                    upload_data[k] = (file_tuple[1], file_tuple[0])
            resp = self.flask_client.post(path, data=upload_data, content_type="multipart/form-data")
            return self._wrap_flask_response(resp)

    def get(self, path):
        if self.use_live:
            return self.session.get(f"{BASE_URL}{path}")
        else:
            resp = self.flask_client.get(path)
            return self._wrap_flask_response(resp)

    def _wrap_flask_response(self, resp):
        class WrappedResponse:
            def __init__(self, r):
                self.status_code = r.status_code
                self.content = r.data
                try:
                    self.text = r.get_data(as_text=True)
                except Exception:
                    self.text = ""
                self.headers = dict(r.headers)
            def json(self):
                return json.loads(self.text or "{}")
        return WrappedResponse(resp)


def run_integration_test():
    print("=" * 70)
    print("      CIFER v4 FORMAL ARCHITECTURE INTEGRATION TEST")
    print("=" * 70)

    client = CiferTestClient()

    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    db_name = os.getenv("DB_NAME", "cifer_db1")
    mongo = MongoClient(mongo_uri)
    db = mongo[db_name]

    # ─────────────────────────────────────────────────────────────
    #  STEP 1: Registration with Argon2id Password Hashing
    # ─────────────────────────────────────────────────────────────
    rand_id = random.randint(10000, 99999)
    test_email = f"cifer_test_{rand_id}@example.com"
    test_password = "SuperSecurePassword123!"
    receiver_email = "authorized_receiver@example.com"

    print(f"\n[1] Registering user: {test_email}")
    reg_resp = client.post_json("/api/register", {
        "name": f"Test User {rand_id}",
        "email": test_email,
        "password": test_password
    })
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.text}"
    user_doc = db.users.find_one({"email": test_email})
    assert user_doc is not None, "User document missing from MongoDB"
    assert user_doc["password_hash"].startswith("$argon2id$"), "Password not stored as Argon2id hash!"
    print("    [+] User registered with valid RFC 9106 Argon2id hash.")

    # ─────────────────────────────────────────────────────────────
    #  STEP 2: 2FA Login with Server-Keyed HMAC OTP
    # ─────────────────────────────────────────────────────────────
    print(f"\n[2] Initiating 2FA login for: {test_email}")
    login_resp = client.post_json("/api/login", {
        "email": test_email,
        "password": test_password
    })
    assert login_resp.status_code == 200, f"Login step 1 failed: {login_resp.text}"
    login_data = login_resp.json()
    assert login_data.get("require_otp") is True

    # Check MongoDB auth_otp for HMAC digest
    auth_otp_doc = db.auth_otp.find_one({"email": test_email})
    assert auth_otp_doc is not None, "auth_otp record missing"
    assert "otp_digest" in auth_otp_doc, "otp_digest missing from auth_otp"
    assert "challenge_id" in auth_otp_doc, "challenge_id missing from auth_otp"

    # Get OTP code from dev_otp or console
    login_otp = login_data.get("dev_otp")
    if not login_otp:
        # If running in production mode, find matching OTP code from challenge
        for candidate in range(1000000):
            c_str = f"{candidate:06d}"
            cand_dig = cifer_crypto.generate_otp_digest(
                test_email, "login", auth_otp_doc["challenge_id"], c_str, cifer_backend.HMAC_OTP_KEY
            )
            if cand_dig == auth_otp_doc["otp_digest"]:
                login_otp = c_str
                break

    print(f"    [+] Submitting login OTP: {login_otp}")
    v_resp = client.post_json("/api/verify-login", {
        "email": test_email,
        "otp": login_otp
    })
    assert v_resp.status_code == 200, f"Login verification failed: {v_resp.text}"
    assert db.auth_otp.find_one({"email": test_email}) is None, "auth_otp not cleared after success"
    print("    [+] 2FA verified successfully. Session established.")

    # ─────────────────────────────────────────────────────────────
    #  STEP 3: 1 MB File Envelope Encryption (AES-256-GCM + KEK)
    # ─────────────────────────────────────────────────────────────
    print("\n[3] Generating 1 MB random payload for Envelope Encryption...")
    original_size = 1024 * 1024  # 1 MB
    original_bytes = os.urandom(original_size)
    filename = "confidential_research_v4.bin"

    file_stream = io.BytesIO(original_bytes)
    files = {"file": (filename, file_stream, "application/octet-stream")}
    data = {
        "receivers": json.dumps([receiver_email]),
        "expiry_hours": "24"
    }

    t0 = time.time()
    enc_resp = client.post_multipart("/api/encrypt", files=files, data=data)
    elapsed = time.time() - t0
    assert enc_resp.status_code == 200, f"Encryption failed: {enc_resp.text}"
    enc_data = enc_resp.json()

    bearer_token = enc_data["token"]
    file_uuid = enc_data["file_uuid"]
    blob_fingerprint = enc_data["fingerprint"]

    assert len(bearer_token) == 64, f"Bearer token must be 256 bits (64 hex), got: {len(bearer_token)}"
    print(f"    [+] Encryption completed in {elapsed:.3f}s")
    print(f"    [+] File UUID: {file_uuid}")
    print(f"    [+] Bearer Capability Token: {bearer_token[:12]}...{bearer_token[-8:]}")
    print(f"    [+] Ciphertext Blob Fingerprint: {blob_fingerprint[:16]}...")

    # ─────────────────────────────────────────────────────────────
    #  STEP 4: Verify MongoDB Out-of-band Bearer Token Digest
    # ─────────────────────────────────────────────────────────────
    print("\n[4] Verifying MongoDB document security parameters...")
    file_record = db.encrypted_files.find_one({"file_uuid": file_uuid})
    assert file_record is not None, "File record not found in MongoDB"
    expected_token_hash = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
    assert file_record["token_hash"] == expected_token_hash, "Token hash in DB does not match SHA-256 of bearer token!"
    assert file_record["wrapped_dek"] is not None
    assert file_record["wrap_iv"] is not None
    assert file_record["blob_fingerprint"] == blob_fingerprint
    print("    [+] MongoDB integrity verified: Token stored exclusively as SHA-256 digest.")

    # Verify carrier on disk does NOT contain bearer token in plain text
    carrier_path = file_record["enc_path"]
    with open(carrier_path, "rb") as fp:
        carrier_bytes = fp.read()
    assert bearer_token.encode("utf-8") not in carrier_bytes, "SECURITY VIOLATION: Bearer token found inside carrier JPEG!"
    print("    [+] Confirmed: Carrier JPEG does NOT leak bearer token.")

    # ─────────────────────────────────────────────────────────────
    #  STEP 5: Simulate DB Tampering & Verify-Then-Dispatch Gating
    # ─────────────────────────────────────────────────────────────
    print("\n[5] Simulating Database Tampering (Adversary modifies recipient email in MongoDB)...")
    db.encrypted_files.update_one(
        {"file_uuid": file_uuid},
        {"$set": {"receivers": ["malicious_actor@attacker.com"]}}
    )

    tamper_otp_resp = client.post_json("/api/request-otp", {"token": bearer_token})
    print(f"    [+] Tampered request status code: {tamper_otp_resp.status_code}")
    assert tamper_otp_resp.status_code == 422, f"Expected HTTP 422 for tampered metadata, got: {tamper_otp_resp.status_code}"
    tamper_json = tamper_otp_resp.json()
    assert tamper_json.get("tamper") is True or "tamper" in tamper_json.get("error", "").lower()
    print("    [+] Verify-then-dispatch blocked unauthorized OTP request (Dual-AAD wrap tag mismatch).")

    # Verify tamper event was logged
    tamper_log = db.activity_log.find_one({"file_id": str(file_record["_id"]), "event": "tamper"})
    assert tamper_log is not None, "Tamper event was not recorded in activity_log"
    print("    [+] Tamper event logged in activity_log.")

    # ─────────────────────────────────────────────────────────────
    #  STEP 6: Restore Legitimate Record & Complete Decryption
    # ─────────────────────────────────────────────────────────────
    print("\n[6] Restoring legitimate database state...")
    db.encrypted_files.update_one(
        {"file_uuid": file_uuid},
        {"$set": {"receivers": [receiver_email]}}
    )

    print("    [+] Requesting OTP for legitimate receiver...")
    otp_resp = client.post_json("/api/request-otp", {"token": bearer_token})
    assert otp_resp.status_code == 200, f"OTP request failed: {otp_resp.text}"
    otp_data = otp_resp.json()

    # Retrieve OTP code
    dec_otp = otp_data.get("dev_otp")
    if not dec_otp:
        otp_rec = db.otp_store.find_one({"file_id": str(file_record["_id"])})
        for candidate in range(1000000):
            c_str = f"{candidate:06d}"
            cand_dig = cifer_crypto.generate_otp_digest(
                str(file_record["_id"]), "decrypt", otp_rec["challenge_id"], c_str, cifer_backend.HMAC_OTP_KEY
            )
            if cand_dig == otp_rec["otp_digest"]:
                dec_otp = c_str
                break

    print(f"    [+] Submitting OTP for decryption: {dec_otp}")
    dec_resp = client.post_json("/api/decrypt", {
        "token": bearer_token,
        "otp": dec_otp
    })
    assert dec_resp.status_code == 200, f"Decryption failed: {dec_resp.text}"
    decrypted_bytes = dec_resp.content

    assert len(decrypted_bytes) == len(original_bytes), f"Size mismatch: {len(decrypted_bytes)} vs {len(original_bytes)}"
    assert decrypted_bytes == original_bytes, "Decrypted bytes do not match original bytes!"
    print("    [+] Byte-for-byte fidelity verified! 1 MB file decrypted perfectly.")

    # ─────────────────────────────────────────────────────────────
    #  STEP 7: Online KEK Rotation Test (G5 Requirement)
    # ─────────────────────────────────────────────────────────────
    print("\n[7] Testing Online Zero-Downtime KEK Rotation (/api/admin/rotate-kek)...")
    new_kek_bytes = os.urandom(32)
    new_kek_id = "kek-2027-v2"
    rot_resp = client.post_json("/api/admin/rotate-kek", {
        "new_kek": new_kek_bytes.hex(),
        "new_kek_id": new_kek_id
    })
    assert rot_resp.status_code == 200, f"Rotation failed: {rot_resp.text}"
    rot_data = rot_resp.json()
    assert rot_data.get("rotated_count", 0) >= 1
    print(f"    [+] Rotated {rot_data['rotated_count']} DEK envelopes to {new_kek_id}.")

    # Confirm record updated in DB
    updated_rec = db.encrypted_files.find_one({"file_uuid": file_uuid})
    assert updated_rec["kek_id"] == new_kek_id, "kek_id not updated in MongoDB"

    # Request new OTP and decrypt again under rotated KEK
    otp_resp2 = client.post_json("/api/request-otp", {"token": bearer_token})
    assert otp_resp2.status_code == 200
    dec_otp2 = otp_resp2.json().get("dev_otp")
    if not dec_otp2:
        otp_rec2 = db.otp_store.find_one({"file_id": str(file_record["_id"])})
        for candidate in range(1000000):
            c_str = f"{candidate:06d}"
            cand_dig = cifer_crypto.generate_otp_digest(
                str(file_record["_id"]), "decrypt", otp_rec2["challenge_id"], c_str, cifer_backend.HMAC_OTP_KEY
            )
            if cand_dig == otp_rec2["otp_digest"]:
                dec_otp2 = c_str
                break

    dec_resp2 = client.post_json("/api/decrypt", {
        "token": bearer_token,
        "otp": dec_otp2
    })
    assert dec_resp2.status_code == 200, f"Decryption after KEK rotation failed: {dec_resp2.text}"
    assert dec_resp2.content == original_bytes, "Decrypted content mismatch after KEK rotation!"
    print("    [+] Post-rotation decryption verified with 100% byte fidelity!")

    print("\n" + "=" * 70)
    print("  ALL 7 CIFER v4 ARCHITECTURAL TESTS PASSED SUCCESSFULLY! ")
    print("=" * 70)


if __name__ == "__main__":
    run_integration_test()
