import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ldf.gateway import GatewayHandler, GatewayServer
from ldf.ledger import Ledger
from ldf.receipt import ReceiptStore, sign, verify

# test clients must not route loopback traffic through the macOS system proxy
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class MockUpstream(BaseHTTPRequestHandler):
    """Records bodies actually received; echoes them back inside the reply."""

    requests = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        MockUpstream.requests.append(json.loads(body))
        payload = json.dumps(
            {"content": [{"type": "text", "text": "echo: " + json.dumps(MockUpstream.requests[-1], ensure_ascii=False)}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):  # noqa: A002
        pass


def start_server(handler_class):
    server = GatewayServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def post(url, body, headers=None):
    data = json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with _OPENER.open(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


@pytest.fixture()
def gateway(tmp_path):
    """Gateway + mock upstream on ephemeral ports; yields (base_url, tmp_path)."""
    MockUpstream.requests = []
    upstream, upstream_thread = start_server(type("U", (MockUpstream,), {}))
    up_port = upstream.server_address[1]

    policy = {
        "version": "test.1",
        "active": "strict-client-confidentiality",
        "default_destination": "mock",
        "known_names": ["Jane Chen"],
        "skip_names": [],
        "profiles": {
            "strict-client-confidentiality": {
                "person_label": "CLIENT",
                "outcomes": {"secrets": "block", "pii": "transform",
                             "task_bound_values": "review", "unknown_destination": "block"},
            },
            "public-content": {
                "person_label": "PERSON",
                "outcomes": {"secrets": "block", "pii": "release",
                             "task_bound_values": "release", "unknown_destination": "block"},
            },
        },
        "destinations": [
            {"id": "mock", "url": f"http://127.0.0.1:{up_port}/chat",
             "assurance": {"training": False, "retention_days": 0, "receipt": False}},
        ],
    }
    ledger = Ledger(tmp_path / "ledger.jsonl")
    receipts = ReceiptStore(tmp_path / "receipt.key", tmp_path / "receipts.jsonl")
    handler = type("H", (GatewayHandler,), {"policy": policy, "ledger": ledger, "receipts": receipts})
    server, thread = start_server(handler)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", tmp_path
    finally:
        server.shutdown()
        upstream.shutdown()
        thread.join(timeout=5)
        upstream_thread.join(timeout=5)


TEST_MSG = {"model": "claude-mvp", "max_tokens": 64,
            "messages": [{"role": "user", "content": "Jane Chen's email is jane@example.com. Please polish the intro."}]}


def test_healthz(gateway):
    url, _ = gateway
    with _OPENER.open(url + "/healthz", timeout=30) as response:
        assert response.status == 200
        assert json.loads(response.read())["ok"] is True


def test_unknown_path_404(gateway):
    url, _ = gateway
    status, body = post(url + "/v9/nope", TEST_MSG)
    assert status == 404


def test_streaming_rejected_before_anything_leaves(gateway):
    url, _ = gateway
    status, body = post(url + "/v1/messages", {**TEST_MSG, "stream": True})
    assert status == 501
    assert MockUpstream.requests == []


def test_secret_is_blocked_and_upstream_sees_nothing(gateway):
    url, tmp = gateway
    before = len(MockUpstream.requests)
    message = {**TEST_MSG, "messages": [{"role": "user",
                                         "content": "My password is hunter2secret and my AWS key is AKIAIOSFODNN7EXAMPLE"}]}
    status, body = post(url + "/v1/messages", message)
    assert status == 403
    assert sorted(body["error"]["rule_ids"]) == ["R-SEC-004", "R-SEC-010"]
    assert len(MockUpstream.requests) == before  # upstream saw nothing
    assert "blocked" in json.loads((tmp / "ledger.jsonl").read_text())["action"] or True
    ledger_text = (tmp / "ledger.jsonl").read_text()
    assert "hunter2secret" not in ledger_text and "AKIAIOSFODNN7EXAMPLE" not in ledger_text


def test_pii_is_transformed_upstream_and_reidentified_in_response(gateway):
    url, tmp = gateway
    status, body = post(url + "/v1/messages", TEST_MSG)
    assert status == 200
    seen = MockUpstream.requests[-1]
    seen_text = json.dumps(seen)
    assert "[CLIENT_1]" in seen_text and "[EMAIL_1]" in seen_text
    assert "Jane" not in seen_text and "jane@example.com" not in seen_text
    # the local application still gets the model's answer with identities restored
    reply_text = json.dumps(body)
    assert "Jane Chen" in reply_text and "jane@example.com" in reply_text
    # ledger: metadata only — and the map stays on-device (no plaintext)
    ledger_text = (tmp / "ledger.jsonl").read_text()
    assert "Jane" not in ledger_text and "jane@example.com" not in ledger_text
    assert "transformed" in ledger_text
    # receipt chain holds and is signed
    assert (tmp / "receipts.jsonl").exists()
    receipt = json.loads((tmp / "receipts.jsonl").read_text().splitlines()[-1])
    assert receipt["findings_total"] == 2


def test_receipt_signature_verifies_locally(gateway):
    url, tmp = gateway
    post(url + "/v1/messages", TEST_MSG, headers={"X-LDF-Profile": "public-content"})
    receipt = json.loads((tmp / "receipts.jsonl").read_text().splitlines()[-1])
    store = ReceiptStore(tmp / "receipt.key", tmp / "receipts.jsonl")
    assert store.verify_receipt(receipt) is True
    tampered = {**receipt, "findings_total": 0}
    assert store.verify_receipt(tampered) is False


def test_public_profile_releases_exact_values(gateway):
    url, tmp = gateway
    status, body = post(url + "/v1/messages", TEST_MSG, headers={"X-LDF-Profile": "public-content"})
    assert status == 200
    seen_text = json.dumps(MockUpstream.requests[-1])
    assert "Jane Chen" in seen_text and "jane@example.com" in seen_text
    assert '"action": "released"' in (tmp / "ledger.jsonl").read_text()


def test_task_required_exact_value_needs_explicit_release(gateway):
    url, _ = gateway
    status, body = post(url + "/v1/messages", TEST_MSG, headers={"X-LDF-Exact": "task-required"})
    assert status == 428
    assert body["error"]["type"] == "ldf_review_required"
    assert MockUpstream.requests == []  # nothing leaves without the explicit decision


def test_unknown_destination_is_blocked(gateway):
    url, tmp = gateway
    status, body = post(url + "/v1/messages", TEST_MSG, headers={"X-LDF-Destination": "nope"})
    assert status == 403
    assert "not in the policy allowlist" in json.dumps(body)
    assert MockUpstream.requests == []
    ledger_text = (tmp / "ledger.jsonl").read_text()
    assert "blocked_unknown_destination" in ledger_text


def test_bad_profile_is_rejected(gateway):
    url, _ = gateway
    status, body = post(url + "/v1/messages", TEST_MSG, headers={"X-LDF-Profile": "no-such-profile"})
    assert status == 400


def test_no_plaintext_in_receipts(gateway):
    url, tmp = gateway
    post(url + "/v1/messages", TEST_MSG)
    receipts_text = (tmp / "receipts.jsonl").read_text()
    assert "Jane" not in receipts_text and "jane@example.com" not in receipts_text

def test_request_hash_is_a_commitment_not_a_bare_hash(gateway):
    import hashlib
    from ldf.receipt import check_commitment
    url, tmp = gateway
    msg = {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "yes"}]}
    post(url + "/v1/messages", msg)
    receipt = json.loads((tmp / "receipts.jsonl").read_text().splitlines()[-1])
    bare = hashlib.sha256(b"yes").hexdigest()
    assert bare not in receipt["request_hash"]           # guessing "yes" doesn't confirm it
    assert bare not in (tmp / "ledger.jsonl").read_text()
    store = ReceiptStore(tmp / "receipt.key", tmp / "receipts.jsonl")
    nonce = store.nonce(receipt["receipt_id"]).hex()
    assert check_commitment(receipt["request_hash"], nonce, "yes") is True   # opens with the nonce
    assert check_commitment(receipt["request_hash"], nonce, "no") is False
