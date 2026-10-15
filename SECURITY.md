# Security Policy

## Reporting a vulnerability

Report privately through GitHub's **Security Advisories** page for this repository
(*Security* → *Report a vulnerability*), not as a public issue.

Please include: what you did, what you expected, what happened, your Chrome/Edge
version, and the extension version (*Extensions* → *Details*).

We aim to acknowledge a report within 3 business days.

**Please do not report a finding and then publish it before we have responded.**
This extension is distributed through two public stores; a disclosure published
before a fix ships puts every user at risk.

## Threat model in one paragraph

This extension is a network-request blocker. The assets worth protecting are the
user's browsing history, credentials and session tokens. The extension holds them
nowhere: analysis runs in the browser process, verdicts are stored locally, and the
only outbound requests are `GET`s for public threat lists. The realistic attack
against it is therefore not data exfiltration — it is a false sense of security
(overstating what is detected) or a bypass that lets a malicious page through while
the user believes it is blocked.

## What a valid report looks like

In scope:

- A URL that produces a `known-malicious` verdict without appearing in a verified feed.
- A page that bypasses a block while the UI claims it was blocked.
- A block we did not cause being counted or attributed to us.
- Content from a feed reaching the DOM or a page unsafely.
- The block record (opaque token in `chrome.storage.session`) being guessable or reusable.
- A message from a web page that changes extension state.

Out of scope:

- Feeds being incomplete or out of date. That is a data problem, not a vulnerability.
- Users wanting cosmetic (element-hiding) ad blocking.
- Any wish for account, sync or cross-device features.
- Theoretical attacks requiring the user to already have installed hostile code.

## Security properties this project enforces in CI

These are asserted by automated checks, so a change that breaks them fails the
build rather than reaching a store:

| Property | Enforced by |
|---|---|
| No credential is ever committed | `scripts/scan-secrets.mjs`, `pre-commit` hook |
| No development-only API is referenced | `tests/unit/privacy-lint.test.ts`, `scripts/static-analysis.mjs` |
| No outbound destination beyond declared public feeds | `scripts/privacy-audit.mjs` |
| No request body, no cookies, no telemetry | `scripts/privacy-audit.mjs` |
| No `eval`, no remote code, no inline script | `scripts/static-analysis.mjs` |
| Strict CSP, no `web_accessible_resources`, no `externally_connectable` | `tests/unit/privacy-lint.test.ts` |
| Content script reads no input values, cookies or storage | `tests/unit/privacy-lint.test.ts` |
| The archive uses `/` separators and loads in a real browser | `tests/unit/zip.test.ts`, `npm run verify:package` |

## On credentials in this repository

The repository is **public**. A credential committed here should be considered
compromised even if it is deleted in a later commit — git history, forks and caches
retain copies, and public repositories are indexed within minutes.

`scripts/scan-secrets.mjs` runs over the working tree and, via the `pre-commit`
hook, over everything staged for commit. Install it once with:

```bash
node scripts/install-hooks.mjs
```

If you find a committed credential, **revoke it first** and only then remove it from
the working tree. Removing without revoking accomplishes nothing.
