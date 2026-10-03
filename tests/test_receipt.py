import os

import pytest

from ldf import receipt as rc
from ldf.gateway import name_coverage_warnings
from ldf.receipt import ALG_ED25519, ALG_HMAC, ReceiptStore, verify

FIELDS = dict(action="released", policy_version="t.1", policy_hash="sha256:x", destination_id="d",
              destination_host="h", request_hash="commit-sha256:00", rule_counts={}, findings_total=0)

needs_crypto = pytest.mark.skipif(not rc.ed25519_available(), reason="cryptography not installed")


@needs_crypto
def test_ed25519_receipt_verifies_with_public_key_only(tmp_path):
    store = ReceiptStore(tmp_path / "receipt.key", tmp_path / "r.jsonl")
    r = store.issue(**FIELDS)
    assert r["alg"] == ALG_ED25519
    pub = store.public_key()
    assert verify(r, pub) is True                      # third party: public key, no secret
    assert verify({**r, "action": "blocked"}, pub) is False
    if os.name != "nt":  # Windows has no POSIX permission bits
        assert (tmp_path / "receipt.ed25519").stat().st_mode & 0o777 == 0o600


@needs_crypto
def test_other_users_public_key_rejects(tmp_path):
    a = ReceiptStore(tmp_path / "a" / "receipt.key", tmp_path / "a" / "r.jsonl")
    b = ReceiptStore(tmp_path / "b" / "receipt.key", tmp_path / "b" / "r.jsonl")
    assert verify(a.issue(**FIELDS), b.public_key()) is False


@needs_crypto
def test_public_key_cannot_forge(tmp_path):
    store = ReceiptStore(tmp_path / "receipt.key", tmp_path / "r.jsonl")
    r = store.issue(**FIELDS)
    # an attacker holding only the public key can MAC with it, but the result is labelled HMAC
    # (not third-party evidence), and relabelling it as Ed25519 fails verification
    forged = rc.sign({k: v for k, v in r.items() if k not in ("signature", "alg", "key_id")}, store.public_key())
    assert forged["alg"] == ALG_HMAC
    assert verify({**forged, "alg": ALG_ED25519, "key_id": r["key_id"]}, store.public_key()) is False


def test_hmac_fallback_is_labelled(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "_ed25519", lambda: None)
    store = ReceiptStore(tmp_path / "receipt.key", tmp_path / "r.jsonl")
    r = store.issue(**FIELDS)
    assert r["alg"] == ALG_HMAC and store.public_key() is None
    assert store.verify_receipt(r) is True
    assert store.verify_receipt({**r, "findings_total": 9}) is False


def test_legacy_receipt_without_alg_still_verifies(tmp_path):
    store = ReceiptStore(tmp_path / "receipt.key", tmp_path / "r.jsonl")
    import hashlib, hmac
    legacy = dict(FIELDS, receipt_id="abc")
    legacy["signature"] = hmac.new(store.key, rc.canonical(legacy), hashlib.sha256).hexdigest()
    assert store.verify_receipt(legacy) is True


def test_name_coverage_warning():
    policy = {"known_names": [], "profiles": {"strict": {"outcomes": {"pii": "transform"}},
                                              "public": {"outcomes": {"pii": "release"}}}}
    warnings = name_coverage_warnings(policy)
    assert len(warnings) == 1 and "strict" in warnings[0] and "public" not in warnings[0]
    assert name_coverage_warnings({**policy, "known_names": ["Jane Chen"]}) == []
