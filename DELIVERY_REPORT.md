# VOLTRIS Browser Shield 1.1.0 — Delivery Report

**Date:** 2026-10-15
**Scope:** Independent Manifest V3 extension for Google Chrome and Microsoft Edge.
**Status:** Implemented, compiled, tested and packaged. Installable now via "Load unpacked".

> **Revision 1.1.0 — pre-publication audit.** A review of 1.0.0 identified that block
> statistics and the explanation page depended on `declarativeNetRequest.onRuleMatchedDebug`,
> which Chrome documents as available **only to unpacked extensions**. In a store install
> both would have failed silently. That finding was correct; it has been fixed at the root
> and is covered by regression tests. Details in §5.

---

## 1. Acceptance criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Chrome and Edge can load the extension | **Met** | Built to `dist/chrome` and `dist/edge`; loaded into a real Chromium in the E2E suite |
| 2 | The popup opens without errors | **Met** | E2E asserts visible render **and zero console/page errors** |
| 3 | The dashboard works | **Met** | E2E renders all 7 sections |
| 4 | Settings persist | **Met** | E2E toggles a setting, reloads, and asserts the value survived |
| 5 | Blocking rules really work | **Met** | E2E seeds fictional threats and asserts the **browser refuses the navigation** |
| 6 | Fictional malicious sites are blocked in tests | **Met** | `phishing-login.test` / `malware-drop.test` (RFC 2606, never resolve) |
| 7 | Heuristic detection identifies controlled examples | **Met** | `paypal.com.secure-login.test` → `suspicious` |
| 8 | The allowlist works | **Met** | Session rule installed/removed; scope verified not to allow `main_frame` |
| 9 | Tracker blocking works | **Met** | EasyPrivacy → DNR rules; E2E asserts the rule set |
| 10 | Lists have verified source and licence | **Met** | `store/FEEDS_AND_LICENSES.md`, each row checked against the publisher's own terms |
| 11 | Updates do not destroy the last valid set | **Met** | Unit-tested; on total failure nothing is written and the revision does not move |
| 12 | Suspicious downloads produce correct alerts | **Met** | `invoice.pdf.exe` → `dangerous`; plain `installer.exe` → `safe` |
| 13 | Statistics correspond to observable events | **Met** | Counters increment **only** from `webNavigation.onErrorOccurred` and download callbacks. E2E asserts the counter advances from a real blocked navigation with the debug API absent |
| 14 | No sensitive data is sent without consent | **Met** | Zero runtime dependencies; privacy-lint test; **build-time privacy audit**; E2E types a password and asserts it never reaches storage |
| 15 | The service worker survives suspension | **Met** | E2E idles, then asserts the first interaction is fully correct |
| 16 | No excessive browser degradation | **Met** | Event-driven only; no `setInterval`; no permanent `MutationObserver`; PSL loaded lazily |
| 17 | Automated tests pass | **Met** | **280 unit + 28 end-to-end = 308 passing** |
| 18 | Privacy policy ready | **Met** | `PRIVACY.md`, shipped inside the package, claims machine-verified by `npm run audit:privacy` |
| 19 | Chrome/Edge packages generated | **Met** | `artifacts/*.zip` + `SHA256SUMS.txt` |

---

## 2. Verification results

| Gate | Command | Result |
|---|---|---|
| Type safety | `npm run typecheck` | **0 errors** (`strict`, `noUncheckedIndexedAccess`) |
| Unit + integration | `npm test` | **280 passed / 12 files** |
| Unit coverage (unit-testable code) | `npm run test:coverage` | **79.8% statements, 72.7% branches, 75.3% functions** |
| Build | `npm run build` | `dist/chrome` and `dist/edge`, 444 KiB each |
| Static analysis of the **built** package | `npm run audit:static` | **Pass** — CSP, permissions, no eval, no remote code, no inline scripts, no unexpected hosts, **no development-only API** |
| Privacy audit of the **built** package | `npm run audit:privacy` | **Pass** — no data-collection path; per-claim evidence printed |
| End-to-end in real Chromium | `npm run test:e2e` | **28 passed** |
| Dependency audit | `npm audit --audit-level=high` | **0 vulnerabilities** |
| Package | `npm run package` | 126 KiB per target |

`npm run verify` chains these in dependency order: **typecheck → test → build →
audit:static → audit:privacy → package**. The audits run *after* the build on purpose.
They previously ran first, which meant they analysed the **previous** build's bytes —
a check that can pass against code that is no longer being shipped. That ordering defect
was found and fixed while auditing the audit.

Coverage note: `src/background`, `src/content` and `src/ui` are excluded from the
**unit** coverage denominator and are verified by the 28 browser-level tests instead —
they require a real `chrome.*` runtime. This is stated in `vitest.config.ts`.

---

## 3. Licence decisions (the part that usually gets skipped)

Every provider was checked against the **publisher's own terms**, not a summary:

| Provider | Licence | Decision |
|---|---|---|
| Phishing.Database | **MIT** (verified at `LICENSE`) | Shipped |
| StevenBlack hosts | **MIT** (verified at `license.txt`) | Shipped, with an aggregation caveat documented |
| EasyList / EasyPrivacy | **GPL-3.0 or CC BY-SA 3.0** | Shipped under the **CC BY-SA 3.0** election; derived data licensed accordingly, code kept separate |
| Public Suffix List | **MPL-2.0** | Generated at build time from a vendored, hashed copy |
| **OpenPhish** | **Prohibits commercial use** | **Excluded.** Terms state: *"not to use any part of the Services for any commercial purposes, including … product development … customer protection"* |
| **URLhaus (abuse.ch)** | Requires Auth-Key; commercial use may need a paid subscription | **Excluded / NOT_CONFIGURED.** No key embedded |
| **PhishTank** | Requires a free app key | **NOT_CONFIGURED** until the user supplies their own key |

No integration is simulated. Providers that are unavailable are **labelled** as such in
Settings → Updates, and the reason is printed in the interface.

---

## 4. Bugs found by the test suite (all fixed)

These are the defects the automated tests caught, listed because they are the most
valuable part of the delivery:

1. **A missing `alarms` permission killed every listener after it.**
   `chrome.alarms` is `undefined` without the permission, so `chrome.alarms.onAlarm.addListener`
   threw and silently prevented the message router, the download listener, the tab
   listener and the block accounting from ever registering. The extension loaded, looked
   fine, and did **nothing**. Fixed by adding the permission *and* making registration
   defensive so one missing API can only disable one capability.
2. **The popup could never talk to the background.** `envelope()` omits the payload when
   there is nothing to send, but the validator required a plain object — so every
   payload-less message type was rejected by its own type guard.
3. **Extension pages opened in a tab were treated as hostile.** The content-script guard
   used `sender.tab !== undefined`, which is also true for the popup/dashboard in a tab.
   Replaced with `sender.url` classification.
4. **The PSL trie walked labels left-to-right while being stored TLD-first**, and the
   exception marker replaced its label, so `!www.ck` matched `foo.ck`. Registrable-domain
   extraction was wrong for every multi-part suffix.
5. **Brand impersonation only matched brands as a suffix**, missing the far more common
   `paypal.com.evil.tld` form.
6. **The Unicode form was lost to punycode conversion** before the homograph engine saw
   it, so fullwidth `ｐaypal` was invisible.
7. **Concurrent block events lost counts** — two callbacks read the
   same snapshot and the second discarded the first's increment.
8. **The update throttle never worked** — `vbs.feedState` was read but never written, so
   every browser start would have hit the network.
9. **Adblock options with values slipped past the deny-list** (`$removeparam=fbclid`),
   so filters we do not understand were applied as if we did.
10. **`chrome.i18n` catalogs contained bare strings**, which makes an entire locale file
    fail to load — the entire Portuguese UI would have silently disappeared.
11. **The hidden switch checkbox was not a reliable hit target**, breaking pointer
    targeting and touch/motor accessibility.
12. **Quota drops were under-reported** in Diagnostics, hiding how much of a feed was
    actually not being enforced.
13. **The dashboard advertised a permission we no longer request.** After removing
    `declarativeNetRequestFeedback`, the Permissions tab still listed it and rendered it
    as *missing* — a table that tells the user we want access we do not have. Now derived
    from the live manifest, so it cannot drift.
14. **A static-analysis check was silently inspecting the wrong build.** `verify` ran the
    audits *before* `build`, so they validated the previous run's output. Found while
    auditing the audit; ordering corrected.

---

## 5. The finding that mattered: statistics built on a development-only API

### What was wrong

1.0.0 counted every matched rule through
`chrome.declarativeNetRequest.onRuleMatchedDebug`. Chrome's own documentation states:

> **onRuleMatchedDebug** — *"Fired when a rule is matched with a request. Only available
> for unpacked extensions with the `declarativeNetRequestFeedback` permission **as this is
> intended to be used for debugging purposes only**."*

> **declarativeNetRequestFeedback** — *"Enables **debugging features for unpacked
> extensions**, specifically `getMatchedRules()` and `onRuleMatchedDebug`."*

The consequences in a published extension were not cosmetic:

- **Every block counter would have read zero** while still rendering as a confident
  number.
- **The explanatory block page would never appear.** A user opening a listed phishing
  site would get Chrome's raw error screen instead of a verdict, the matching feed, and
  a gated bypass. This was the most serious consequence: a *missing feature*, not a
  cosmetic one, and it would have shipped.

The 300 tests passed because they ran against an unpacked build — the one configuration
where the API exists. The suite was structurally incapable of catching this.

### What was done

| | Before | After |
|---|---|---|
| Permission | requested `declarativeNetRequestFeedback` | **removed** |
| Block detection | `onRuleMatchedDebug` | **`webNavigation.onErrorOccurred`**, main frame + `net::ERR_BLOCKED_BY_CLIENT` only |
| Attribution | decoded from the rule id | **verified against our own threat dataset** |
| Tab id | recovered by scanning `chrome.tabs` | **provided directly by the event** |
| Attribution display | `rule #12345` | the **feed and domain** that matched |
| Statistics | per-request, all resource types | **blocked pages** (observable), rule count (state), detections, downloads |

The attribution step matters: `net::ERR_BLOCKED_BY_CLIENT` also fires when **another
extension** blocks a request. A blocked URL is claimed as ours only when it resolves in
our own local dataset to a category that is currently enabled. Otherwise it is dropped —
neither counted nor shown as our verdict.

### Why this is a real measurement, not an estimate

A counter is incremented only from an event the browser reported to us, and only when we
have independently confirmed the event was ours. It is never inferred from the rule
count, and it is never extrapolated.

### What is honestly declared impossible

Chrome offers **no production API** for counting blocked sub-resources (images, scripts,
trackers). Rather than show a convincing `0`, the dashboard says so:

> Blocked sub-resources (images, scripts, trackers) — **Not measurable**
> *"Not measurable in a published extension. The browser exposes this counter only to
> unpacked, development builds, so we report no number rather than an invented one."*

The list is driven by `METRIC_CAPABILITIES` in `src/core/types.ts`, which the service
worker publishes and the dashboard renders, so the disclosure cannot drift from reality.

### Regression coverage

| Test | Asserts |
|---|---|
| `runs with the unpacked-only matched-rule feed absent` | the permission is not declared **and** the API is genuinely absent — so the whole suite runs in the production configuration |
| `a blocked navigation is counted with the debug API unavailable` | the counter advances from a real blocked navigation, and the event is attributed to the feed, not to a `rule:` id |
| `a block we did not cause is not claimed as ours` | a DNS failure produces no counter change and no interstitial |
| `the dashboard discloses which metrics cannot be measured` | exactly one metric is labelled unavailable, on its own row |
| `privacy-lint` | no shipped source references `onRuleMatchedDebug`, `getMatchedRules` or the feedback permission |
| `static-analysis` | the **built** package contains none of those symbols and neither dev-only permission |

The `privacy-lint` check strips comments first, so the modules that *document* why the
API is not used are not mistaken for uses of it.

---

## 6. Privacy audit

`npm run audit:privacy` inspects the **built package** — what actually gets published —
and prints evidence per claim rather than asserting a conclusion. It verifies:

1. No data-access permission is declared (no `cookies`, `history`, `bookmarks`, `topSites`,
   `webRequest`, `nativeMessaging`, `clipboard*`, `browsingData`, `desktopCapture`,
   `sessions`, `geolocation`, `proxy`, `debugger`, …).
2. `<all_urls>` is the only host permission.
3. No `externally_connectable` and no `web_accessible_resources`.
4. Every outbound host in the built JavaScript is a feed host declared in the registry.
5. No analytics, telemetry or tracking host appears anywhere in the package.
6. Every `fetch` sets `credentials: 'omit'` — no cookie can ever be attached.
7. No `fetch` carries a body and none uses a non-`GET` method.
8. Any credential header is the user's own API key, sent only to the provider that issued
   it, and only when the user supplied it. The audit **verifies the provider-id gating**
   rather than trusting a comment.
9. No local storage key holds passwords, cookies, tokens or page content.

**The audit corrected two of my own false claims.** Its first version asserted "no custom
headers". That was wrong: the feed fetcher sends `Accept: text/plain, */*` and, for the two
opt-in credentialed providers, the user's API key. Rather than weaken the check, the
audit now enumerates the headers, explains each, and verifies the provider gating — and
`PRIVACY.md` §5 states the behaviour plainly. It also initially missed the credential
headers entirely, because minification rewrites `authkey: v` into `h.authkey = v`; both
forms are now detected, since a check that passes because it cannot see the thing it is
checking is worse than no check.

Two limits are stated in `PRIVACY.md` rather than papered over: the audit cannot show
that the browser itself logs nothing, and a list download is an ordinary HTTPS request,
so the feed publisher sees your IP address. That is true of any internet download, is not
used to build a profile, and is disclosed rather than implied away.

---

## 7. Honest limitations

Stated in the product itself, in `store/LIMITATIONS.md`:

- Cannot detect every malicious site; feeds only cover reported URLs.
- Cannot predict server-side redirects.
- Does not expand URL shorteners automatically (would require sending browsing data
  third-party or fetching attacker-controlled destinations).
- Does not scan file contents and is **not** an antivirus; it never replaces or disables
  the browser's own download protections.
- Threat feeds exceed Chrome's 30,000-rule cap. Rules are prioritised and **every drop
  is counted and named** in Diagnostics; a truncated list is never shown as complete.
- Cosmetic (element-hiding) adblock rules cannot be converted to network rules; they are
  counted and reported as not enforced.
- **No bundled feed publishes cryptographic signatures.** We record and display SHA-256
  hashes but do not claim signature verification.
- **Per-request block counts are unavailable in a published build** and are declared as
  such rather than faked (§5).
- **The extension has not been trialed from an actual store install.** Every claim about
  production behaviour rests on Chrome's API documentation and on a suite that runs in
  the shipped permission configuration — not on an observed store deployment.

---

## 8. Deliverables

```
dist/chrome/                     Load-unpacked target for Chrome
dist/edge/                       Load-unpacked target for Edge
artifacts/voltris-browser-shield-1.1.0-chrome.zip
artifacts/voltris-browser-shield-1.1.0-edge.zip
artifacts/SHA256SUMS.txt

PRIVACY.md                       Store-compliant privacy policy (also shipped in the package)
THIRD_PARTY_NOTICES.md           Licences and attribution
store/FEEDS_AND_LICENSES.md      Per-provider verification record
store/LIMITATIONS.md             What it cannot do
store/THREAT_MODEL.md            Assets, boundaries, threats, mitigations
store/INSTALL.md                 Installation and troubleshooting
store/PUBLISH_CHECKLIST.md       Store submission checklist
README.md                        Architecture and design decisions
```

## 9. What remains for you

These require your accounts and decisions; the engineering is done:

1. Create the Chrome Web Store and Microsoft Edge Add-ons developer accounts.
2. Produce the five store screenshots (list in `store/PUBLISH_CHECKLIST.md` §4).
3. Confirm the `VOLTRIS` trademark and the `privacy@voltris.com` address.
4. Upload the ZIPs and declare **no data collection**. `PRIVACY.md` §9 lists the
   machine-verified evidence if a reviewer asks for it.

---

## 8. Reproducing the verification

```powershell
npm ci
npm run verify      # typecheck + static analysis + 276 unit tests + build + package
npm run test:e2e    # 24 tests in a real Chromium with the extension loaded
npm audit --audit-level=high
```
