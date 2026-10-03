# Publish checklist — ldf-mvp (first public release)

Everything before `git push`. Checked items are done.

- [x] License: MIT, © Richard Z. Chen (LICENSE)
- [x] Security contact: richardchen2008@outlook.com (SECURITY.md)
- [x] Maintainer triage: Outlook rules + habits (MAINTAINER-OUTLOOK-RULES.md)
- [x] RFC 9116 file present (security.txt) — **with placeholders to fill (step 3)**
- [x] CHANGELOG v0.1.1, README, 39 tests, dist zip + SHA256SUMS

## 1. Name check (before anything public)

Search GitHub + general web for "Local Disclosure Firewall" collisions; note
any existing product with the same name and consider a suffix if needed.

## 2. Create the public repo

GitHub → new repository → **ldf-mvp** (under your account). Push the

    working tree; tag v0.1.1.

## 3. Fill the security.txt placeholders — ✓ DONE (Oct 2, 2026; URLs now under github.com/mooppss/ldf-mvp)

Two fields contain the final URL, which doesn't exist until the repo is
created:

    Canonical: https://example.invalid/.well-known/security.txt
    Policy:    https://github.com/RICHARD-CHEN-PLACEHOLDER/ldf-mvp/blob/main/SECURITY.md

**GitHub-only (no domain):**

    Canonical: https://github.com/<your-username>/ldf-mvp/blob/main/security.txt
    Policy:    https://github.com/<your-username>/ldf-mvp/blob/main/SECURITY.md

**With a domain (if the project ever gets one):** serve the file at
`https://<domain>/.well-known/security.txt` (that exact lowercase path) and
set Canonical to that URL.

An unfilled file is deliberately useless (example.invalid) — but it must not
SHIP filled with placeholders.

## 4. GitHub settings (once, in the repo)

- Security tab → Private vulnerability reporting → **Enable** (reports then
  arrive as GitHub notifications, filed by Outlook Rule 3).
- Set the maintainer email/contact in the repo's About/description if desired.
- Add the sponsor link (GitHub Sponsors / Ko-fi) — the README placeholder.

## 5. Verify the artifact

    shasum -a 256 -c SHA256SUMS     # in dist/ — attach the zip + checksums
                                    # to the v0.1.1 GitHub release

## 6. Post-publish

- Rebuild `dist/` once more AFTER the security.txt edit (the zip embeds it).
- Check the published SECURITY.md renders, and that the receipt/ledger docs
  match (nothing in the README claims what the code doesn't do).
- Yearly: renew the `Expires` line in security.txt (calendar: Oct 1).