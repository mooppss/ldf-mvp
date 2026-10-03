"""The gateway: a local HTTP proxy that makes the disclosure decision.

Applications point at 127.0.0.1:<port> instead of the provider. POST
/v1/messages (Anthropic-style) or /v1/chat/completions (OpenAI-style);
the gateway scans the request's text fields, applies the active
profile's outcomes, and either:

  blocks      -> 403 (nothing leaves; plain-language explanation + rule ids)
  transformed -> substituted text forwarded; response re-identified locally
  released    -> forwarded as written (still logged and receipted)
  review      -> 428 (needs an explicit local decision before anything leaves)

Every decision is recorded in the ledger (metadata only, never
plaintext) and receipted with a signed receipt (Ed25519 when available).
"""
from __future__ import annotations

import http.server
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from . import __version__
from .detectors import Finding, scan_text
from .ledger import Ledger
from .policy import find_destination, outcome_for, policy_hash, validate_upstream_url
from .receipt import ReceiptStore, new_receipt_id
from .transform import SubstitutionMap

SAFELISTED_PASSTHROUGH = ("authorization", "x-api-key", "anthropic-version", "user-agent")
SUPPORTED_PATHS = ("/v1/messages", "/v1/chat/completions")

# Forwarder connects DIRECTLY: the gateway is the disclosure decision point, so
# environment/system proxies (which are themselves undeclared destinations) are
# bypassed by default. The ZCode incident is the cautionary example: 564
# delivery attempts nobody declared. Documented in the README.
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def extract_text_refs(body: Any) -> list[tuple[dict, str]]:
    """All (container, key) pairs in the request that carry disclosure text.

    Covers both flavors generically: the top-level "system" string
    (Anthropic), any "content" string, and any "text" field in structured
    blocks/parts — wherever they sit in the request tree.
    """
    refs: list[tuple[dict, str]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and key in ("system", "content", "text"):
                    refs.append((node, key))
                elif isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(body)
    return refs


def reidentify_tree(node: Any, submap: SubstitutionMap) -> Any:
    if isinstance(node, dict):
        return {k: reidentify_tree(v, submap) for k, v in node.items()}
    if isinstance(node, list):
        return [reidentify_tree(v, submap) for v in node]
    if isinstance(node, str):
        return submap.reidentify(node)
    return node


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    server_version = "LDF/" + __version__
    protocol_version = "HTTP/1.1"

    # wired by serve()
    policy: dict = {}
    ledger: Ledger = Ledger(Path("/dev/null"))
    receipts: ReceiptStore = ReceiptStore(Path("/tmp/ldf-unused-key"), Path("/tmp/ldf-unused-receipts"))

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        # Never log request paths or headers (paths can quote sensitive content).
        pass

    # -- responses ---------------------------------------------------------
    def _send_json(self, status: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _explain_block(self, rule_ids, destination_id, extra: str = "") -> dict:
        return {
            "error": {
                "type": "ldf_blocked",
                "message": (
                    "Blocked: a credential or secret pattern was detected; nothing left this device. "
                    "Move the secret to your secret store and re-send without it."
                    if rule_ids else
                    "Blocked: unknown destination. Nothing left this device. Add the destination to your "
                    "policy file and address it with the X-LDF-Destination header."
                ) + (extra or ""),
                "rule_ids": rule_ids,
                "destination": destination_id,
            }
        }

    # -- http --------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {"ok": True, "ldf": __version__, "policy_hash": policy_hash(self.policy)})
        else:
            self._send_json(404, {"error": {"type": "not_found", "message": "GET is only supported on /healthz."}})

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except (BrokenPipeError, ConnectionResetError):
            raise
        except Exception as exc:  # noqa: BLE001 - keep the gateway alive; report generically
            try:
                self._send_json(500, {"error": {"type": "ldf_internal", "message": f"Gateway error: {type(exc).__name__}. Nothing was forwarded by this handler."}})
            except Exception:
                pass

    def _handle_post(self) -> None:
        if self.path not in SUPPORTED_PATHS:
            self._send_json(404, {"error": {"type": "not_found", "message": f"POST supported on {' or '.join(SUPPORTED_PATHS)} only."}})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": {"type": "ldf_bad_request", "message": "Request body must be JSON."}})
            return

        if body.get("stream"):
            self._send_json(501, {"error": {"type": "ldf_unsupported", "message": 'MVP gateway supports non-streaming requests only. Set "stream": false.'}})
            return

        profile_name = self.headers.get("X-LDF-Profile") or self.policy.get("active")
        profile = self.policy["profiles"].get(profile_name)
        if profile is None:
            self._send_json(400, {"error": {"type": "ldf_bad_request", "message": f"Unknown profile '{profile_name}'. Available: {', '.join(sorted(self.policy['profiles']))}."}})
            return
        outcomes = profile.get("outcomes", {})

        destination = find_destination(self.policy, self.headers.get("X-LDF-Destination"))
        destination_id = destination["id"] if destination else (self.headers.get("X-LDF-Destination") or None)
        scheme_problem = destination and validate_upstream_url(destination["url"])

        refs = extract_text_refs(body)
        per_ref = [(node, key, node[key], scan_text(node[key],
                                                    self.policy.get("known_names", []),
                                                    self.policy.get("skip_names", [])))
                   for node, key in refs]
        findings = [f for _, _, _, found in per_ref for f in found]
        originals = [text for _, _, text, _ in per_ref]
        rule_counts: dict[str, int] = {}
        for f in findings:
            rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
        # commitment, not a bare hash: short prompts can't be confirmed by hashing guesses
        receipt_id = new_receipt_id()
        request_hash = self.receipts.commit(receipt_id, "\n".join(originals))
        host = urlsplit(destination["url"]).netloc if destination else None

        def record(action: str, submap: Optional[SubstitutionMap] = None) -> dict:
            receipt = self.receipts.issue(
                action=action, policy_version=self.policy["version"], policy_hash=policy_hash(self.policy),
                destination_id=destination_id, destination_host=host, request_hash=request_hash,
                rule_counts=rule_counts, findings_total=len(findings), ldf_version=__version__,
                receipt_id=receipt_id)
            self.ledger.record(
                action=action, rule_counts=rule_counts, findings_total=len(findings),
                policy_hash=policy_hash(self.policy), policy_version=self.policy["version"],
                destination_id=destination_id, destination_host=host, path=self.path,
                request_hash=request_hash, bytes_original=sum(len(t) for t in originals),
                receipt_id=receipt["receipt_id"],
                map_ephemeral=submap is not None)  # MVP: map is in-process only, never written
            return receipt

        # -- decisions ------------------------------------------------------
        if unknown_destination := (destination is None or scheme_problem is not None):
            action = outcome_for(profile, "unknown_destination")
            reason = (f"Destination '{destination_id}' is not in the policy allowlist." if destination is None
                      else f"Destination refused: {scheme_problem}")
            if action == "block":
                record("blocked_unknown_destination")
                self._send_json(403, self._explain_block([], destination_id, extra=f" ({reason})") if destination is None else
                                {"error": {"type": "ldf_blocked", "message": f"Blocked: {reason} Nothing left this device.", "destination": destination_id}})
                return
            record("review_required", None)
            self._send_json(428, {"error": {"type": "ldf_review_required", "message": f"Review required: {reason}", "destination": destination_id}})
            return

        secrets = [f for f in findings if f.category == "secret"]
        if secrets:  # paper rule 1: hard block in every profile
            block_rules = sorted({f.rule_id for f in secrets})
            record("blocked")
            self._send_json(403, self._explain_block(block_rules, destination_id))
            return

        pii_outcome = outcome_for(profile, "pii")
        exact_wanted = (self.headers.get("X-LDF-Exact") or "").strip().lower() == "task-required"
        if exact_wanted:
            pii_outcome = outcome_for(profile, "task_bound_values")

        if pii_outcome == "review":
            record("review_required")
            kinds = sorted({f.kind.replace("_", " ") for f in findings if f.category == "pii"})
            self._send_json(428, {"error": {
                "type": "ldf_review_required",
                "message": ("Review required: this request carries identity values ("
                            + ", ".join(kinds) + ") and this profile does not release exact values. "
                            "Send without X-LDF-Exact, or switch profiles to release them explicitly."),
                "rule_counts": rule_counts, "destination": destination_id}})
            return

        submap: Optional[SubstitutionMap] = None
        if pii_outcome == "transform" and any(f.category == "pii" for f in findings):
            submap = SubstitutionMap(person_label=profile.get("person_label", "CLIENT"))
            for node, key, text, found in per_ref:
                node[key] = submap.apply(text, [f for f in found if f.category == "pii"])

        action = "transformed" if submap is not None else ("released" if pii_outcome == "release" else "transformed_clean")
        record(action, submap)

        status, payload, resp_headers = self._forward(destination["url"], body)
        if submap is not None and payload:
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, (dict, list)):
                    payload = json.dumps(reidentify_tree(parsed, submap), ensure_ascii=False).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        self.send_response(status)
        ctype = next((v for k, v in resp_headers.items() if k.lower() == "content-type"), "application/json")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # -- upstream ----------------------------------------------------------
    def _forward(self, url: str, body: dict) -> tuple[int, bytes, dict]:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": self.server_version}
        for name in SAFELISTED_PASSTHROUGH:
            value = self.headers.get(name)
            if value and name != "user-agent":
                headers[name] = value
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with _DIRECT_OPENER.open(request, timeout=60) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            except Exception:
                payload = b""
            return exc.code, payload or b"{}", dict(exc.headers or {})
        except urllib.error.URLError as exc:
            payload = json.dumps({"error": {"type": "ldf_upstream_unreachable",
                                            "message": f"Could not reach {urlsplit(url).netloc}: {exc.reason}"}}).encode("utf-8")
            return 502, payload, {"Content-Type": "application/json"}


def name_coverage_warnings(policy: dict) -> list[str]:
    """Flag profiles that rely on name transformation with no known_names list.

    The name detector is precision-first: only honorific/greeting-cued names
    are caught, so bare mentions ("Smith emailed...") pass through unless the
    name is listed in known_names.
    """
    if policy.get("known_names"):
        return []
    transforming = sorted(name for name, prof in policy.get("profiles", {}).items()
                          if prof.get("outcomes", {}).get("pii") == "transform")
    if not transforming:
        return []
    return [f"known_names is empty but profile(s) {', '.join(transforming)} transform identities. "
            "Only names after a cue (Dear, Hi, Mr., Dr., ...) will be caught; bare mentions like "
            "'Smith emailed me' are sent as written. Add recurring client/person names to "
            "known_names in your policy file."]


class GatewayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(policy_path: Path, port: int = 8765, home: Optional[Path] = None) -> None:
    from .policy import load_policy
    home = Path(home) if home else Path.home() / ".ldf"
    policy = load_policy(policy_path)
    ledger = Ledger(home / "ledger.jsonl")
    receipts = ReceiptStore(home / "receipt.key", home / "receipts.jsonl")
    handler = type("BoundGateway", (GatewayHandler,), {
        "policy": policy, "ledger": ledger, "receipts": receipts,
    })
    server = GatewayServer(("127.0.0.1", port), handler)
    print(f"LDF gateway on http://127.0.0.1:{port} | policy {policy['version']} "
          f"{policy_hash(policy)} | profile {policy['active']}", flush=True)
    for warning in name_coverage_warnings(policy):
        print(f"WARNING: {warning}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()