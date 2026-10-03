# Changelog

All notable changes to the Local Disclosure Firewall (LDF). Every user-facing
version line states what it adds; preregistration discipline applies to
behavioral claims, not just experiment readouts.

## 0.1.1 — 2026-10-02

- Receipts: Ed25519 signatures when the optional `cryptography` package is
  installed, so anyone holding the public key can verify a receipt without
  being able to forge one. HMAC-SHA256 remains the dependency-free fallback and
  is now labelled (`"alg"` field). Receipts from 0.1.0 (no `alg`) still verify.
- New: `receipts --export-public-key`, `receipts --reveal <id>`, and
  `verify-receipt` for third-party checks.
- `request_hash` is now a per-receipt commitment, `sha256(nonce ‖ text)`, not a
  bare SHA-256 of the prompt, so short or predictable prompts can't be confirmed
  by hashing guesses. Receipt ids are random.
- `init`, `serve` and `doctor` warn when `known_names` is empty while a profile
  transforms identities (uncued names are otherwise sent as written).
- Docs: removed a local filesystem path from the README and package docstring.
- 39 tests.

## 0.1.0 — 2026-10-01

Initial MVP release.

- Gateway: local HTTP proxy for Anthropic-style (`/v1/messages`) and
  OpenAI-style (`/v1/chat/completions`) requests; direct forwarding (bypasses
  system/environment proxies by design — the gateway is the declared egress
  point); non-streaming only (`stream: true` refused before any scan).
- Policy engine: versioned JSON policy; three profiles
  (strict-client-confidentiality / ordinary-business-use / public-content);
  per-request overrides (`X-LDF-Profile`, `X-LDF-Exact: task-required` →
  review-or-release for task-needed exact values).
- Detectors: secrets always hard-blocked (10 rules: OpenAI/Anthropic/GitHub/
  AWS/Google keys, Slack tokens, JWTs, Bearer tokens, PEM blocks, credential
  assignments); PII: emails, Luhn-checked cards, guarded SSNs, phones, and
  precision-first person names (honorific/greeting cues + policy `known_names`).
- Transformation: stable placeholders per value (`[CLIENT_1]`, `[EMAIL_1]`…);
  responses re-identified locally before the application sees them;
  substitution map in-process only by default (optional encrypted-at-rest
  persistence requires the `cryptography` package).
- Ledger: metadata only (action, rule counts, policy hash, destination,
  request hash) — never plaintext.
- Receipts: locally signed (HMAC-SHA256, user-held key) — the sender-side
  provenance mark.
- 32 tests; end-to-end demo (`demo_e2e.py`).

Known limits in v0.1.0 (see README): name detection is precision-first
(uncued mentions pass), no streaming, gateway covers only traffic routed
through it (full toolchain egress needs an OS firewall), not a certification
product.