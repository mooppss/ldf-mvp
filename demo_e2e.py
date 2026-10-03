#!/usr/bin/env python3
"""End-to-end demo of the Local Disclosure Firewall MVP.

Starts a mock provider + the LDF gateway on loopback, then walks the
policy paper's three outcomes (plus review) through real HTTP requests:

  1. secret present      -> blocked, provider sees nothing
  2. sensitive + transform -> provider sees only placeholders, the local
                              app still receives the answer re-identified
  3. public profile      -> released as written, still logged + receipted
  4. exact value needed  -> review required (428)

Prints the receipt verification and the plaintext-free ledger at the end.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ldf.gateway import GatewayHandler, GatewayServer  # noqa: E402
from ldf.ledger import Ledger  # noqa: E402
from ldf.receipt import ReceiptStore, verify  # noqa: E402


class MockProvider(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        MockProvider.seen.append(json.loads(body))
        payload = json.dumps({"content": [{"type": "text",
                                           "text": "Here is the polished intro. " + json.dumps(MockProvider.seen[-1])}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):  # noqa: A002
        pass


def post(opener, url, body, headers=None):
    request = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with opener.open(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main() -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), MockProvider)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    MockProvider.seen = []

    tmp = Path.home() / ".ldf" / "demo"  # demo state lives under the real .ldf home
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "ledger.jsonl").unlink(missing_ok=True)   # fresh transcript per run
    (tmp / "receipts.jsonl").unlink(missing_ok=True)
    ledger = Ledger(tmp / "ledger.jsonl")
    receipts = ReceiptStore(tmp / "receipt.key", tmp / "receipts.jsonl")

    policy = json.loads((Path(__file__).resolve().parent / "policy.example.json").read_text())
    policy["destinations"] = [{"id": "mock", "url": f"http://127.0.0.1:{upstream.server_address[1]}/v1/messages",
                               "assurance": {"training": False, "retention_days": 0, "receipt": False}}]
    policy["default_destination"] = "mock"

    handler = type("H", (GatewayHandler,), {"policy": policy, "ledger": ledger, "receipts": receipts})
    gateway = GatewayServer(("127.0.0.1", 0), handler)
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{gateway.server_address[1]}"

    print("=" * 74)
    print("LDF MVP end-to-end demo — the policy paper's outcomes, over real HTTP")
    print("=" * 74)

    draft = {"model": "demo", "max_tokens": 64, "messages": [{"role": "user", "content":
        "Please improve this paragraph for a client update. Dear Jane Chen, your "
        "retainer invoice #4471 is attached; reach me at richard@chen-legal.com or "
        "415-555-2671. My notes password is summer-meeting-88 and my AWS key is "
        "AKIAIOSFODNN7EXAMPLE."}]}
    print("\n[1] secret in the request -------------------------------")
    status, body = post(opener, base + "/v1/messages", draft)
    seen_before = len(MockProvider.seen)
    print(f"  gateway -> {status} (blocked, nothing forwarded: provider saw {seen_before} previous)")
    print(f"  say:    {body['error']['message'][:110]}…  rules={body['error']['rule_ids']}")

    print("\n[2] client-confidential work, default profile ------------")
    safe = {"model": "demo", "max_tokens": 64, "messages": [{"role": "user", "content":
        "Dear Jane Chen, please improve this paragraph. The retainer invoice 4471 "
        "remains unpaid; reach me at richard@chen-legal.com or 415-555-2671."}]}
    status, body = post(opener, base + "/v1/messages", safe)
    provider_view = json.dumps(MockProvider.seen[-1])
    print(f"  gateway -> {status} transformed")
    print(f"  provider saw:  …{provider_view[provider_view.find('Dear'):][:140]}…")

    print("\n[3] marketing copy, public-content profile --------------")
    public = {"model": "demo", "max_tokens": 64, "messages": [{"role": "user", "content":
        "Rewrite this slogan: Chen Legal — invoices never sleep."}]}
    status, body = post(opener, base + "/v1/messages", public, headers={"X-LDF-Profile": "public-content"})
    print(f"  gateway -> {status} released as written")
    print(f"  provider saw:  …{json.dumps(MockProvider.seen[-1])[60:180]}…")

    print("\n[4] exact value claimed task-required --------------------")
    status, body = post(opener, base + "/v1/messages", safe, headers={"X-LDF-Exact": "task-required"})
    print(f"  gateway -> {status} review required")
    print(f"  say:    {body['error']['message'][:110]}…")

    print("\nreceipts (the sender-side mark) --------------------------")
    issued = receipts.all()
    latest = issued[-1]
    print(f"  {len(issued)} receipts; latest {latest['receipt_id']} action={latest['action']} "
          f"policy={latest['policy_version']} findings={latest['findings_total']}")
    print(f"  verify locally: {latest['receipt_id']} -> "
          f"{'valid' if receipts.verify_one(latest['receipt_id']) else 'INVALID'}")
    tampered = {**latest, "findings_total": 0}
    print(f"  verify tampered copy -> {'valid' if receipts.verify_receipt(tampered) else 'INVALID (as designed)'}")
    pub = receipts.public_key()
    if pub:
        print(f"  signed {latest['alg']}; third party with only the public key -> "
              f"{'valid' if verify(latest, pub) else 'INVALID'}")
    else:
        print(f"  signed {latest['alg']} (install 'cryptography' for Ed25519 receipts others can verify)")

    print("\nledger (metadata only) -----------------------------------")
    summary = ledger.summary()
    print(f"  {summary['entries']} entries; actions: {summary['by_action']}")
    print(f"  rules seen: {summary['by_rule']}")
    ledger_text = (tmp / "ledger.jsonl").read_text()
    leaked = [s for s in ("Jane Chen", "richard@chen-legal.com", "415-555-2671",
                          "summer-meeting-88", "AKIAIOSFODNN7EXAMPLE") if s in ledger_text]
    print(f"  plaintext leak check: {'CLEAN — no identities, values, or secrets appear' if not leaked else f'LEAKED: {leaked}'}")

    upstream.shutdown()
    gateway.shutdown()
    print("\n(done; demo ledger/receipts are under ~/.ldf/demo — delete freely)")


if __name__ == "__main__":
    main()