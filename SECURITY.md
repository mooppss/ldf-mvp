# Security Policy — Local Disclosure Firewall (LDF)

## Supported

- Version 0.1.x (the current MVP line).

## Reporting a vulnerability

Email **richardchen2008@outlook.com** (Richard Chen's mailbox).

Please include: the LDF version, the rule or module involved, a minimal
reproduction (a sample request is fine — **redact real secrets and client
names**), and the observed vs expected behavior.

- Acknowledgment within 5 business days.
- No bounty program in the MVP stage; credited thanks in the changelog.
- Maintainer-side setup (folder, Outlook triage rules, GitHub private
  reporting): see `MAINTAINER-OUTLOOK-RULES.md`.

## What the software itself collects: nothing

- No telemetry, no phone-home, no crash reporting, no analytics.
- The receipts key, receipt ledger, and decision ledger live only in the
  user's `~/.ldf/` directory and never leave the machine through this
  software. (Network activity is limited to the user's own configured
  provider calls, forwarded directly.)
- Distribution artifacts ship with SHA256 checksums
  (`release.sh` → `dist/SHA256SUMS`); verify before running.

## Out of scope for "security" claims

LDF is a disclosure-decision layer, not a sandbox: it cannot protect data on
an already-compromised machine, and it does not replace per-provider contracts.
The README's "Limits" section is part of the security documentation, not a
disclaimer appendix.