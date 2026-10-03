# Maintainer: Outlook triage rules for the LDF security mailbox

The published SECURITY.md points reporters at **richardchen2008@outlook.com**.
This file is the maintainer-side setup: folder, rules, and the two habits that
keep a public security mailbox from becoming either a landfill or an attack
surface. Written for **Outlook on the web** (richardchen2008@outlook.com is
Outlook.com) — desktop-Outlook variants are noted where they differ.

## 0. One folder

On the web: **Settings ⚙ → Mail → Folders → Create new folder** → name it
**`LDF Security`**.

## 1. The rules (Settings ⚙ → Mail → Rules → Add new rule)

Apply in this order. Each rule that moves mail gets **"Stop processing more
rules"** checked, so a message is filed exactly once.

### Rule 1 — "LDF: security keywords"

- **Condition:** Subject or body includes any of:
  `vulnerability` · `security report` · `CVE` · `exploit` · `proof of concept`
  · `exfiltrate` · `exfiltration` · `disclosure` · `reproduce`
- **Actions:** Move to → `LDF Security`; Mark as high importance;
  ✅ Stop processing more rules.

This catches reports that never name the product ("found a bug in your
gateway tool…").

### Rule 2 — "LDF: product name"

- **Condition:** Subject or body includes any of:
  `Local Disclosure Firewall` · `LDF` · `ldf-mvp`
- **Actions:** Move to → `LDF Security`; ✅ Stop processing more rules.

"would / helpful / field" do **not** contain the substring "LDF" — false
positives at English word level are negligible.

### Rule 3 — "LDF: GitHub notifications"

- **Condition:** From → contains `github.com`
- **Actions:** Move to → `LDF Security`; ✅ Stop processing more rules.

Covers private vulnerability reports and advisory updates if the GitHub repo
is the front door (see §3 below — this is the recommended main channel).

## 2. Two habits that matter more than any rule

1. **Junk bypasses rules.** Outlook.com rules only fire on the Inbox. A real
   report with a scary subject line can land in Junk and sit there for weeks.
   Check Junk for anything LDF-related **weekly**; marking one as "not junk"
   trains the filter for the next report. (Desktop Outlook can add a rule for
   Junk-folder scanning; the web UI cannot — hence the habit.)
2. **The security mailbox is itself an attack surface.** A public "report
   security issues" address receives unsolicited attachments — treat every
   attachment in every report as untrusted (preview off, scan before opening),
   and never auto-forward reports anywhere: forwarding is exactly how a
   0-day escapes early, and it contradicts the coordinated-disclosure promise
   in SECURITY.md.

## 3. Prefer GitHub private reporting as the front door

GitHub → repo → **Security tab → Private vulnerability reporting → Enable**.
Reports then arrive as GitHub notifications (land in `LDF Security` via Rule
3) instead of raw email, with no attachment-loading in the personal mailbox
and built-in private coordination. Keep the email address for reporters who
follow SECURITY.md without touching GitHub.

Both channels are listed in the repo's `security.txt` (the RFC 9116 file that
lets tools and reporters discover the reporting channel mechanically).

## 4. Acknowledgment promise (what SECURITY.md registered)

- Acknowledge within **5 business days** of a report arriving in
  `LDF Security` (or via GitHub).
- Credit reporters in the changelog (unless they ask otherwise).

That's the entire triage system: one folder, three rules, two habits.