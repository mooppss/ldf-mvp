"""Command line interface for the Local Disclosure Firewall MVP."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

HOME = Path.home() / ".ldf"
EXAMPLE_POLICY = Path(__file__).resolve().parent.parent / "policy.example.json"


def _home(args) -> Path:
    return Path(args.home).expanduser()


def _store(home: Path):
    from .receipt import ReceiptStore
    return ReceiptStore(home / "receipt.key", home / "receipts.jsonl")


def cmd_init(args) -> int:
    home = _home(args)
    home.mkdir(parents=True, exist_ok=True)
    policy_path = home / "policy.json"
    if not policy_path.exists():
        if not EXAMPLE_POLICY.exists():
            print(f"Example policy not found at {EXAMPLE_POLICY}", file=sys.stderr)
            return 2
        shutil.copy(EXAMPLE_POLICY, policy_path)
        os.chmod(policy_path, 0o600)
    store = _store(home)
    from .gateway import name_coverage_warnings
    from .policy import load_policy, policy_hash
    policy = load_policy(policy_path)
    print(f"Policy:      {policy_path}")
    print(f"Secret key:  {home / 'receipt.key'} (kept local — move to your OS keychain for production)")
    if store.public_key():
        print(f"Signing:     Ed25519, private key {store.signing_key_path}")
        print(f"Public key:  {store.public_key().hex()}  (share this so others can verify your receipts)")
    else:
        print("Signing:     HMAC-SHA256 fallback — receipts are verifiable only by you.")
        print("             pip install cryptography, then re-run init, for Ed25519 receipts anyone can verify.")
    print(f"Active:      {policy['active']}")
    print(f"Policy hash: {policy_hash(policy)}")
    for warning in name_coverage_warnings(policy):
        print(f"Warning:     {warning}")
    print("Next:        python -m ldf.cli serve")
    return 0


def cmd_serve(args) -> int:
    from .gateway import serve
    serve(Path(args.policy).expanduser(), port=args.port, home=_home(args))
    return 0


def cmd_policy(args) -> int:
    from .policy import load_policy, policy_hash
    policy = load_policy(Path(args.policy).expanduser())
    print(json.dumps({"version": policy["version"], "active": policy["active"],
                      "policy_hash": policy_hash(policy),
                      "profiles": {name: profile["outcomes"] for name, profile in policy["profiles"].items()},
                      "destinations": [{"id": d["id"], "url": d["url"], "assurance": d["assurance"]}
                                       for d in policy.get("destinations", [])]},
                     indent=2, ensure_ascii=False))
    return 0


def cmd_ledger(args) -> int:
    from .ledger import Ledger
    print(json.dumps(Ledger(_home(args) / "ledger.jsonl").summary(), indent=2))
    return 0


def cmd_receipts(args) -> int:
    store = _store(_home(args))
    receipts = store.all()
    if args.export_public_key:
        pub = store.public_key()
        if pub is None:
            print("No Ed25519 key: install the 'cryptography' package and re-run `init`.", file=sys.stderr)
            return 1
        print(pub.hex())
        return 0
    if args.reveal:
        receipt = store.find(args.reveal)
        if receipt is None:
            print(json.dumps({"receipt_id": args.reveal, "verdict": "not found"}))
            return 1
        print(json.dumps({"receipt": receipt, "nonce": store.nonce(args.reveal).hex(),
                          "note": "Give this nonce plus the exact disclosed text to a verifier; it opens this "
                                  "receipt's request_hash only. Never share receipt.key."}, indent=2))
        return 0
    if args.verify:
        verdict = store.verify_one(args.verify)
        print(json.dumps({"receipt_id": args.verify,
                          "verdict": {None: "not found", True: "valid", False: "INVALID"}[verdict]}))
        return 0 if verdict else 1
    print(json.dumps({"count": len(receipts),
                      "alg": store.alg,
                      "all_valid": all(store.verify_receipt(r) for r in receipts),
                      "recent": [{"receipt_id": r["receipt_id"], "ts": r["ts"], "action": r["action"],
                                  "destination_id": r["destination_id"], "findings_total": r["findings_total"]}
                                 for r in receipts[-10:]]}, indent=2))
    return 0


def cmd_verify_receipt(args) -> int:
    """Third-party verification: needs only the receipt and the signer's public key."""
    from .receipt import ALG_ED25519, check_commitment, verify
    receipt = json.loads(Path(args.receipt).expanduser().read_text(encoding="utf-8"))
    receipt = receipt.get("receipt", receipt)  # accept `receipts --reveal` output directly
    if receipt.get("alg") != ALG_ED25519:
        print(json.dumps({"verdict": "UNVERIFIABLE",
                          "reason": f"receipt alg is {receipt.get('alg', 'HMAC-SHA256')}; only the signer can check it"}))
        return 1
    ok = verify(receipt, bytes.fromhex(args.public_key.strip()))
    result = {"receipt_id": receipt.get("receipt_id"), "signature": "valid" if ok else "INVALID"}
    if args.nonce and args.text_file:
        text = Path(args.text_file).expanduser().read_text(encoding="utf-8")
        result["content_matches"] = check_commitment(receipt.get("request_hash", ""), args.nonce, text)
        ok = ok and result["content_matches"]
    print(json.dumps(result))
    return 0 if ok else 1


def cmd_doctor(args) -> int:
    from .policy import load_policy, policy_hash, validate_upstream_url
    home = _home(args)
    checks = []
    advisories = []  # shown as [warn]; never fail doctor
    policy_path = home / "policy.json"
    checks.append(("policy.json exists", policy_path.exists()))
    key_path = home / "receipt.key"
    checks.append(("receipt key exists", key_path.exists()))
    if key_path.exists():
        checks.append(("receipt key permission 0600", (key_path.stat().st_mode & 0o777) == 0o600))
    from .receipt import ed25519_available
    signing_path = home / "receipt.ed25519"
    advisories.append(("Ed25519 signing available (else HMAC receipts only you can verify; pip install cryptography)",
                       ed25519_available()))
    if signing_path.exists():
        checks.append(("signing key permission 0600", (signing_path.stat().st_mode & 0o777) == 0o600))
    if policy_path.exists():
        try:
            policy = load_policy(policy_path)
            checks.append(("policy valid", True))
            for dest in policy.get("destinations", []):
                reason = validate_upstream_url(dest["url"])
                checks.append((f"destination '{dest['id']}' acceptable", reason is None))
            from .gateway import name_coverage_warnings
            warnings = name_coverage_warnings(policy)
            advisories.append(("known_names set for name-transforming profiles", not warnings))
        except Exception as exc:  # noqa: BLE001
            checks.append(("policy valid", False))
            print(f"  policy error: {exc}")
    for name, ok in checks:
        print(f"[{'ok' if ok else 'FAIL'}] {name}")
    for name, ok in advisories:
        print(f"[{'ok' if ok else 'warn'}] {name}")
    return 0 if all(ok for _, ok in checks) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ldf", description="Local Disclosure Firewall (MVP)")
    parser.add_argument("--home", default=str(HOME), help="LDF state directory (default ~/.ldf)")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create policy + local receipt key")
    init.set_defaults(func=cmd_init)

    serve = sub.add_parser("serve", help="run the gateway on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--policy", default=str(HOME / "policy.json"))
    serve.set_defaults(func=cmd_serve)

    pol = sub.add_parser("policy", help="show the active policy and its hash")
    pol.add_argument("--policy", default=str(HOME / "policy.json"))
    pol.set_defaults(func=cmd_policy)

    led = sub.add_parser("ledger", help="ledger summary (metadata only, never plaintext)")
    led.set_defaults(func=cmd_ledger)

    rec = sub.add_parser("receipts", help="list/verify signed receipts")
    rec.add_argument("--verify", help="receipt id to verify")
    rec.add_argument("--reveal", help="print a receipt plus its commitment nonce (to prove what it covered)")
    rec.add_argument("--export-public-key", action="store_true", help="print the Ed25519 public key (hex)")
    rec.set_defaults(func=cmd_receipts)

    ver = sub.add_parser("verify-receipt", help="verify someone's receipt with their public key")
    ver.add_argument("receipt", help="receipt JSON file (or `receipts --reveal` output)")
    ver.add_argument("--public-key", required=True, help="signer's Ed25519 public key (hex)")
    ver.add_argument("--nonce", help="commitment nonce from the signer (hex)")
    ver.add_argument("--text-file", help="the disclosed text, to check against request_hash")
    ver.set_defaults(func=cmd_verify_receipt)

    doc = sub.add_parser("doctor", help="check install health")
    doc.set_defaults(func=cmd_doctor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())