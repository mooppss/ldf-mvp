"""Signed request receipts — the sender-side mark.

Policy paper (Oct 1, 2026 revision): the supplier now holds a durable
provenance instrument over everything it produces (the Claude text
watermark); the small user should hold the equal-and-opposite
instrument over everything they disclose. A receipt is exactly that:
a durable provenance record the user holds — a commitment to what was
disclosed, the policy version, the endpoint and the date — signed with
a key that lives only on the user's device.

Signatures
----------
* Ed25519 (default when the optional ``cryptography`` package is
  installed). The private key never leaves ``~/.ldf``; the public key can
  be handed to anyone (``ldf receipts --export-public-key``), and a third
  party can then verify a receipt without being able to forge one.
* HMAC-SHA256 (fallback, no dependencies). Symmetric: only the key holder
  can verify, and the key holder could also produce a receipt. Receipts
  carry ``"alg": "HMAC-SHA256"`` so nobody mistakes them for third-party
  verifiable evidence.

Request commitment
------------------
``request_hash`` is not a bare SHA-256 of the prompt (a short, predictable
prompt could be confirmed by hashing guesses). It is a commitment:
``sha256(nonce || text)`` where ``nonce = HMAC(local_secret, receipt_id)``.
Without the nonce the hash reveals nothing guessable; to prove what was
disclosed in one receipt, the user reveals that receipt's nonce
(``ldf receipts --reveal <id>``) together with the text, and anyone can
recompute it with :func:`check_commitment`. Revealing one nonce reveals
nothing about any other receipt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ALG_ED25519 = "Ed25519"
ALG_HMAC = "HMAC-SHA256"
COMMIT_PREFIX = "commit-sha256:"


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519
    except ImportError:
        return None


def ed25519_available() -> bool:
    return _ed25519() is not None


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def ensure_key(path: Path) -> bytes:
    """Local 32-byte secret: HMAC fallback signing + commitment nonces."""
    path = Path(path)
    if not path.exists():
        _write_secret(path, os.urandom(32))
    path.chmod(0o600)
    return path.read_bytes()


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def canonical(receipt: dict[str, Any]) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign(receipt: dict[str, Any], key: bytes, *, signing_key=None) -> dict[str, Any]:
    """Sign with Ed25519 if ``signing_key`` is given, else HMAC with ``key``."""
    receipt = dict(receipt)
    if signing_key is not None:
        from cryptography.hazmat.primitives import serialization
        pub = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        receipt["alg"] = ALG_ED25519
        receipt["key_id"] = key_id(pub)
        receipt["signature"] = signing_key.sign(canonical(receipt)).hex()
    else:
        receipt["alg"] = ALG_HMAC
        receipt.pop("key_id", None)
        receipt["signature"] = hmac.new(key, canonical(receipt), hashlib.sha256).hexdigest()
    return receipt


def verify(receipt: dict[str, Any], key: bytes) -> bool:
    """Verify a receipt.

    ``key`` is the 32-byte raw Ed25519 *public* key for Ed25519 receipts
    (anyone can hold it), or the local HMAC secret for HMAC receipts.
    """
    claimed = receipt.get("signature")
    if not claimed:
        return False
    alg = receipt.get("alg", ALG_HMAC)  # receipts from v0.1.0 had no alg field
    if alg == ALG_ED25519:
        ed = _ed25519()
        if ed is None or receipt.get("key_id") != key_id(key):
            return False
        try:
            ed.Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(claimed), canonical(receipt))
            return True
        except Exception:  # noqa: BLE001 - InvalidSignature, bad hex, bad key
            return False
    if alg == ALG_HMAC:
        expected = hmac.new(key, canonical(receipt), hashlib.sha256).hexdigest()
        return hmac.compare_digest(claimed, expected)
    return False


def new_receipt_id() -> str:
    return os.urandom(8).hex()


def check_commitment(commitment: str, nonce_hex: str, text: str) -> bool:
    """Third-party check that ``text`` is what a receipt committed to."""
    if not commitment.startswith(COMMIT_PREFIX):
        return False
    digest = hashlib.sha256(bytes.fromhex(nonce_hex) + text.encode("utf-8")).hexdigest()
    return hmac.compare_digest(commitment[len(COMMIT_PREFIX):], digest)


class ReceiptStore:
    """Append-only store of signed receipts (one JSON object per line)."""

    def __init__(self, key_path: Path, store_path: Path, signing_key_path: Optional[Path] = None):
        key_path = Path(key_path)
        self.key = ensure_key(key_path)
        self.store_path = Path(store_path)
        self.signing_key_path = Path(signing_key_path) if signing_key_path else key_path.with_name("receipt.ed25519")
        self._signing_key = self._load_or_create_signing_key()

    # -- keys ----------------------------------------------------------------
    def _load_or_create_signing_key(self):
        ed = _ed25519()
        if ed is None:
            return None
        if not self.signing_key_path.exists():
            _write_secret(self.signing_key_path, os.urandom(32))
        self.signing_key_path.chmod(0o600)
        return ed.Ed25519PrivateKey.from_private_bytes(self.signing_key_path.read_bytes())

    @property
    def alg(self) -> str:
        return ALG_ED25519 if self._signing_key is not None else ALG_HMAC

    def public_key(self) -> Optional[bytes]:
        if self._signing_key is None:
            return None
        from cryptography.hazmat.primitives import serialization
        return self._signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def verification_key(self, receipt: dict[str, Any]) -> bytes:
        if receipt.get("alg") == ALG_ED25519:
            return self.public_key() or b""
        return self.key

    # -- commitments -----------------------------------------------------------
    def nonce(self, receipt_id: str) -> bytes:
        return hmac.new(self.key, b"ldf-commit|" + receipt_id.encode("utf-8"), hashlib.sha256).digest()

    def commit(self, receipt_id: str, text: str) -> str:
        return COMMIT_PREFIX + hashlib.sha256(self.nonce(receipt_id) + text.encode("utf-8")).hexdigest()

    # -- receipts --------------------------------------------------------------
    def issue(self, *, action: str, policy_version: str, policy_hash: str,
              destination_id: Optional[str], destination_host: Optional[str],
              request_hash: str, rule_counts: dict[str, int], findings_total: int,
              ldf_version: str = "0.1", receipt_id: Optional[str] = None) -> dict[str, Any]:
        receipt = {
            "receipt_id": receipt_id or new_receipt_id(),
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "destination_id": destination_id,
            "destination_host": destination_host,
            "request_hash": request_hash,
            "rule_counts": rule_counts,
            "findings_total": findings_total,
            "ldf_version": ldf_version,
        }
        receipt = sign(receipt, self.key, signing_key=self._signing_key)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self.store_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, ensure_ascii=True) + "\n")
        return receipt

    def all(self) -> list[dict[str, Any]]:
        if not self.store_path.exists():
            return []
        return [json.loads(line) for line in self.store_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def find(self, receipt_id: str) -> Optional[dict[str, Any]]:
        for receipt in self.all():
            if receipt.get("receipt_id") == receipt_id:
                return receipt
        return None

    def verify_receipt(self, receipt: dict[str, Any]) -> bool:
        return verify(receipt, self.verification_key(receipt))

    def verify_one(self, receipt_id: str) -> Optional[bool]:
        receipt = self.find(receipt_id)
        return None if receipt is None else self.verify_receipt(receipt)
