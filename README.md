# Local Disclosure Firewall (LDF) — MVP

A runnable MVP of the control proposed in the accompanying policy paper:
a user-controlled gateway for prompts and text documents. Applications
send requests to the gateway instead of directly to a cloud model; the
gateway makes a disclosure decision **locally**, applies the user's
policy, and records what happened.

```
 your apps (curl, SDK, agent)                the internet
        │                                             ▲
        ▼                                             │
 ┌──────────────────┐  policy decision   ┌──────────────┴─────────┐
 │  LDF gateway      │  ────────────▶    │ provider endpoint       │
 │  127.0.0.1:8765   │  transform first  │ (allowlisted in policy) │
 └──────────────────┘                    └────────────────────────┘
   detectors · substitution map (in-process) · ledger · signed receipts
```

## Quickstart

```bash
cd ldf-mvp
python3 -m ldf.cli init                       # policy + local receipt key (~/.ldf)
python3 -m ldf.cli serve                      # gateway on http://127.0.0.1:8765
```

Then point any OpenAI/Anthropic-style client at `http://127.0.0.1:8765` instead
of the provider. Example through the gateway:

```bash
# NOTE: curl and local SDKs may route 127.0.0.1 through the system proxy.
curl --noproxy '*' http://127.0.0.1:8765/v1/messages \
  -H 'x-api-key: $PROVIDER_KEY' -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-3-5-sonnet","max_tokens":64,
       "messages":[{"role":"user","content":"Dear Jane Chen, please polish this note."}]}'
```

The default `strict-client-confidentiality` profile transforms identity values
before anything leaves: the provider sees `Dear [CLIENT_1], please polish this
note.` — and your local app still receives the answer with `Jane Chen` restored.

Inspect a session:

```bash
python3 -m ldf.cli policy      # active profile + policy hash + destinations
python3 -m ldf.cli ledger      # decisions so far (metadata only — never plaintext)
python3 -m ldf.cli receipts    # signed receipts; --verify <id> checks the local signature
python3 -m ldf.cli doctor      # install health
python3 demo_e2e.py            # guided demo of all four outcomes
python3 -m pytest -q           # 39 tests
```

## The five rules → the code

| Policy paper rule | Where it lives |
|---|---|
| 1. Credentials and secrets are blocked | `ldf/detectors.py` (`R-SEC-001…010`), enforced in every profile |
| 2. Identity not necessary for the task is transformed locally | `ldf/transform.py` + profile `pii: transform` |
| 3. Exact values are an explicit release decision | `X-LDF-Exact: task-required` header → the profile's `task_bound_values` outcome (`review` by default) |
| 4. Unknown provider behavior is a risk signal | destination allowlist (`policy.destinations`); undeclared or non-https (except loopback tests) destinations fail closed |
| 5. The provider boundary includes the client software | out of MVP scope for enforcement — see *Limits* below |

Outcomes, in plain language: **Blocked** (403 — nothing leaves; explanation +
rule ids), **Transformed** (forwarded with substitutions; the reply is
re-identified before your app sees it), **Released** (forwarded as written,
still logged and receipted), plus **Review** (428) for decisions that need an
explicit human choice.

## Receipts: the sender-side mark

Revised policy paper (Oct 2026): suppliers now hold a durable provenance
instrument over everything they produce (the Claude text watermark under the EU
transparency code of practice). The gateway mirrors it for the user: every
decision is receipted with a signed record — a commitment to what was
disclosed, the policy version, the destination, the date — signed with a key
that lives only on your device. Receipts establish what you disclosed without
logging plaintext, exactly as the supplier's watermark establishes what it
produced without identifying a person.

**Signatures.** With the optional `cryptography` package installed
(`pip install cryptography`), receipts are signed with **Ed25519**: the private
key stays in `~/.ldf/receipt.ed25519`, and anyone you give the public key to
can verify a receipt but cannot forge one. Without it, LDF falls back to
**HMAC-SHA256**, which only you can verify (and which you could, in principle,
fabricate), so those receipts are labelled `"alg": "HMAC-SHA256"` and are
personal records, not evidence for a third party. `ldf doctor` tells you which
mode you're in.

**Request commitment.** `request_hash` is `sha256(nonce ‖ text)` with a
per-receipt nonce derived from your local secret, not a bare hash of the
prompt, so nobody holding your receipts or ledger can confirm a short or
predictable prompt by hashing guesses. To prove what one receipt covered, reveal
that receipt's nonce together with the text; other receipts stay closed.

```bash
python3 -m ldf.cli receipts                       # list; alg + all_valid flag
python3 -m ldf.cli receipts --verify 68963a53…    # verify one receipt locally
python3 -m ldf.cli receipts --export-public-key   # hex Ed25519 key to share
python3 -m ldf.cli receipts --reveal 68963a53… > receipt.json   # receipt + its nonce

# a third party, with only your public key, the receipt and the text:
python3 -m ldf.cli verify-receipt receipt.json --public-key <hex> \
    --nonce <hex> --text-file disclosed.txt
```

## Limits (declared, not discovered)

- **Not perfect privacy.** A compromised endpoint reads text before the gateway
  acts; a provider can still infer people from residual context. The enforceable
  claim: what is removed before transmission is unavailable downstream.
- **Name detection is precision-first — fill in `known_names`.** Only
  explicitly cued names (honorifics, greetings) and your `known_names` list are
  transformed; an uncued mention ("Later Smith emailed…") **is sent as
  written**. For client work, list every recurring client and person name in
  `known_names` in `~/.ldf/policy.json`. `init`, `serve` and `doctor` warn
  while the list is empty and a profile transforms identities.
- **The gateway covers the traffic that points at it.** The ZCode incident
  (September 2026) showed client-side upload channels operating entirely outside
  the prompt path. Full toolchain egress control is an operating-system firewall
  job (Little Snitch / a `pf` anchor allowing only the gateway and declared
  hosts); this MVP ships the decision layer and points at the enforcement layer.
- **Substitution maps are per-request and in-process by default** — never
  written unless you explicitly ask for encrypted persistence (requires the
  optional `cryptography` package).
- **Providers' secrets in headers pass through by design** (that is the
  provider-authentication channel); the detectors police content, headers are
  never logged.
- **No streaming** (SSE) in the MVP; stream requests are refused before
  anything is scanned or sent.
- This is **not a certification product** and none of it removes contractual or
  legal obligations.

## Roadmap

Provider-side machine-readable assurance metadata fetched at send time (the
policy file's `assurance` fields are hand-maintained in the MVP); OS keychain
for the receipt key; streaming support; an optional local NER model for name
recall; verifiable/reproducible client builds (the ZCode aftermath made the
case); ingestion of provider-signed assurance receipts.

## License & distribution

**MIT — free shareware.** Free to use, copy, share, modify, and redistribute,
including commercially; copyright Richard Z. Chen 2026. This is honor-ware: if
it earns its keep in your practice, consider supporting the author (placeholder
for a GitHub Sponsors / Ko-fi link in the published repo). The license includes
the standard no-warranty disclaimer; this is a disclosure-decision aid, not a
certification product, and it does not replace contracts or legal obligations.

**Privacy of this software:** it collects nothing, phones home never, and works
offline except for the provider calls you configure.

**Verify your download:** release zips ship with a checksum file
(`dist/SHA256SUMS`, produced by `release.sh`):

```bash
shasum -a 256 -c SHA256SUMS
```

## Files

```
ldf-mvp/
  policy.example.json     the three profiles + destination allowlist
  ldf/policy.py           loading, hashing, allowlist
  ldf/detectors.py        secret + PII recognizers (rule ids = ledger trail)
  ldf/transform.py        stable substitution + offline re-identification
  ldf/ledger.py           metadata-only decision log
  ldf/receipt.py          signed receipts + request commitments (the sender-side mark)
  ldf/gateway.py          the decision point (proxy for both API flavors)
  ldf/cli.py              init / serve / policy / ledger / receipts / doctor
  demo_e2e.py             guided demo of all outcomes over real HTTP
  tests/                  39 tests (detectors, transform, receipts, gateway e2e)
  security.txt            RFC 9116 reporting-channel file (fill URLs at publish)
  MAINTAINER-OUTLOOK-RULES.md — mailbox folder + triage rules + habits
  PUBLISH-CHECKLIST.md    ordered list for the first public release
```