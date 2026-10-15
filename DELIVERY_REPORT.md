# VOLTRIS Browser Shield 1.2.0 — Delivery Report

**Date:** 2026-10-15
**Scope:** Independent Manifest V3 extension for Google Chrome and Microsoft Edge.
**Status:** Implemented, compiled, tested and packaged. Installable now via "Load unpacked".

> **Revision 1.2.0 — the extension did not protect anyone.**
>
> User testing of 1.1.0 found that no phishing, malware or scam site was detected, and that
> ads were not blocked. The cause was not a weak list or a missed heuristic: **the feed
> pipeline produced nothing at all, so zero blocking rules were ever installed.** The popup
> still showed protection "On".
>
> Every one of the 336 previous tests passed, because every one of them seeded threats
> directly into storage and so never touched the path that was broken. Details in §5.

---

## 0. Read this first

Three faults shipped in earlier revisions. All three shared one property: **they could not
be seen by the tests that existed, and none of them produced an error.**

| Revision | Fault | What the user saw |
|---|---|---|
| 1.0.0 | Statistics and the block explanation page used an API that does not exist in a published extension | Counters frozen at zero; a raw browser error page instead of our verdict |
| 1.1.0 | The ZIP used `\` as a path separator, which the Chrome Web Store cannot read | Upload rejected; `short_name` and `description` over the store's character limits |
| 1.1.0 | **The threat dataset exceeded the storage ceiling, so no feed was ever stored** | **No protection at all, reported as working** |

The third is the reason this report leads with a warning rather than a summary. A security
product that fails open while reporting success is worse than one that visibly breaks,
because the user has no reason to look for the problem.

---

## 0b. What the 1.2.0 fix changed

| | Before | After |
|---|---|---|
| `storage.local` ceiling | 10 MB, refused the ~27 MiB dataset | `unlimitedStorage`, ceiling raised |
| Dataset cap | 6 MiB in the updater, 9 MiB in `persistDataset` | 64 MiB, documented with the measurements |
| Feed download cap | 32 MiB, rejected the 65.8 MiB link feed | 128 MiB |
| Phishing link feed URL | pointed at a file the publisher serves **empty** | pointed at the populated file |
| Rule budget | counted **per provider**, so `ad` used 2× its share | one shared budget per category |
| Which hosts win the budget | first N alphabetically, i.e. mostly `0.0.0.0.*` | an even stride across the whole list |
| When no rules are installed | nothing said so | the popup and Settings both say it, in plain language |
| When an update cycle throws | `catch {}`, silently | recorded, shown, and listed as threat data to delete |

Measured on a fresh install after the fix:

```
phishing-database-domains   active    386,093 entries
stevenblack-hosts           active     73,278 entries
easylist                    active     50,335 entries
easyprivacy                 active     47,235 entries
phishing-database-links     active         (hosts extracted from 65.8 MB of URLs)

dynamic rules installed: 24,000
  phishing 13,000   malware 5,000   tracker 3,500   ads 2,500
```

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
| 17 | Automated tests pass | **Met** | **319 unit + 46 end-to-end = 365 passing** |
| 18 | Privacy policy ready | **Met** | `PRIVACY.md`, shipped inside the package, claims machine-verified by `npm run audit:privacy` |
| 19 | Chrome/Edge packages generated | **Met** | `artifacts/*.zip` + `SHA256SUMS.txt` |
| **20** | **Blocking rules are actually installed on a real install** | **Met (after a serious fault)** | `tests/e2e/feeds.spec.ts` downloads the **real** feeds and asserts >1,000 rules exist. This is the criterion that was previously unverified and was silently failing |

---

## 2. Verification results

| Gate | Command | Result |
|---|---|---|
| Type safety | `npm run typecheck` | **0 errors** (`strict`, `noUncheckedIndexedAccess`) |
| Unit + integration | `npm test` | **319 passed / 14 files** |
| Build | `npm run build` | `dist/chrome` and `dist/edge` |
| Static analysis of the **built** package | `npm run audit:static` | **Pass** — CSP, permissions, no eval, no remote code, no inline scripts, no unexpected hosts, **no development-only API** |
| Privacy audit of the **built** package | `npm run audit:privacy` | **Pass** — no data-collection path; per-claim evidence printed |
| End-to-end, offline | `npm run test:e2e -- --project=chromium-extension` | **36 passed** |
| **End-to-end, real threat feeds** | `npm run test:e2e:live` | **10 passed** — real download, real rules, real block |
| Packaged archive loads | `npm run verify:package` | **Pass** |
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
15. **The store archive used `\` as a path separator.** PowerShell's `Compress-Archive` on
    Windows PowerShell 5.1 writes backslashes, which violates APPNOTE 4.4.17.1 and which the
    Chrome Web Store cannot read. Replaced with a dependency-free ZIP writer, verified by
    reading the archive back with .NET — an implementation we did not write — and by
    loading the extracted package into a real browser.
16. **`short_name` was 14 characters against a 12-character store limit, and `description`
    was 198 against 132.** Both would have been rejected at upload, with an error that does
    not name the field. `tests/unit/store-limits.test.ts` now pins both in both locales.
17. **The Settings button did nothing.** `chrome.runtime.openOptionsPage()` requires the
    manifest to declare `options_ui` or `options_page`; ours declared neither, so the button
    rendered correctly and silently failed. Found by the user, confirmed by the
    `Could not create an options page` error in their console.
18. **The dashboard did not follow the language override.** It wrote its heading and tab bar
    before the override loaded, leaving the page half-translated.
19. **Popup renders were not serialised.** A burst of change events let two renders
    interleave between clearing the root and writing, producing two `<select>` elements
    sharing the id `ui-language`.
20. **Two Playwright projects shared one browser profile.** Chromium profiles persist, so
    the live-feeds job's data and settings leaked into the offline suite. This surfaced as
    two flaky failures that were really isolation bugs.
21. **A favicon probe could never work.** Chrome's `_favicon/` endpoint returns a valid PNG
    with no `Content-Type` header, so `new Image()` fails to decode it. Referencing the URL
    directly in CSS works. Found by testing rather than by reading documentation — the
    `favicon` API page is not where one would look.

---

## 5a. The fault that mattered: the extension blocked nothing

### How it was found

The user installed 1.1.0, visited phishing and malware sites, and saw no detection. The
first instinct is to blame the lists or the heuristics. Measuring instead of guessing
gave a different answer: on a fresh install, **0 dynamic rules**.

Every one of the 336 tests passed. All of them seeded threats directly into
`chrome.storage`, which is correct for testing behaviour and completely bypasses the feed
pipeline — the pipeline that was broken.

### The chain of causes

Four independent defects, each of which alone was fatal:

**1. The dataset exceeded the storage ceiling.**
Measured against the real feeds on 2026-10-15:

| Provider | Entries | Packed size |
|---|---|---|
| phishing-database-domains | 386,093 | 20.83 MiB |
| stevenblack-hosts | 73,278 | 2.90 MiB |
| easylist | 50,327 | 1.84 MiB |
| easyprivacy | 47,235 | 1.91 MiB |
| **total** | | **27.47 MiB** |

`chrome.storage.local` allows 10 MB without `unlimitedStorage`. The updater refused
every download, and on a fresh install there is no previous dataset to preserve, so
nothing was written at all.

**2. Two separate dataset caps, both below the real size** — 6 MiB in `updateFeeds` and
9 MiB in `persistDataset`. Both were guesses, and both failed closed.

**3. The phishing link feed pointed at a file the publisher serves empty.**
`phishing-links-ACTIVE-today.txt` returns HTTP 200 with **0 bytes** (verified). The
populated file is `phishing-links-ACTIVE.txt` at 65.8 MB, which the 32 MiB download cap
would then have rejected anyway.

**4. The rule budget was counted per provider.** `ad` is contributed by two providers, so
the category could install twice its documented 2,000 rules and consume quota the threat
categories needed.

### Why it failed silently

Two suppression points turned a hard failure into a non-event:

- `runUpdateCycle` ended in `catch {}`. A total failure produced no log, no history entry,
  no state — and no error the user could see.
- `ensureRules` returns quietly. A build that compiles nothing is indistinguishable from
  a build with an empty dataset, so the popup rendered a normal "protection On" screen
  with a rule count of zero.

That is the part worth remembering. Neither defect was exotic; the combination is what
made the extension *look* fine while protecting nothing.

### What changed

| | Before | After |
|---|---|---|
| Storage | 10 MB ceiling | `unlimitedStorage` |
| Dataset caps | 6 MiB / 9 MiB | one documented 64 MiB ceiling |
| Download cap | 32 MiB | 128 MiB |
| Link feed URL | empty file | populated file |
| Budget | per provider | shared per category |
| Host selection | first N alphabetically | even stride across the list |
| Failure handling | `catch {}` | recorded, surfaced, deletable |

### The rule-budget bug, in detail

Worth stating precisely because it produced a rule set that *looked* like work.

Feeds arrive sorted ASCII, and the per-category loop took hosts in that order until the
budget ran out. The first 2,000 ad hosts in sorted order are all domains beginning with
`0` and `a`. The installed rules were literally:

```
||0.0.0.0.creative.hpyrdr.com^
||0.0.0.0.hpyrdr.com^
||0.athwartwhoafat.com^
...
```

Real rules, correct syntax, thousands of them, blocking nothing anyone visits. An
even-stride sample across the sorted list produces a genuine spread — the same install now
covers 11+ starting letters per category.

### Why truncation was rejected as a fix

Keeping the dataset small enough to fit an arbitrary byte budget was considered and
rejected. The feeds are sorted ASCII, so the retained subset would have been every domain
beginning with a few letters — a biased sample presented as complete. Silently dropping
known phishing domains is the exact failure mode this project criticises elsewhere, so
storage was raised instead.

### Regression coverage

`tests/e2e/feeds.spec.ts` is a new Playwright project that hits the network, because the
offline suite was structurally incapable of catching this. It asserts:

- the cycle completes without throwing and writes a dataset;
- every credential-free provider is `active` with >1,000 entries;
- >1,000 rules are installed after a fresh install;
- threats outweigh privacy categories in the budget;
- no category exceeds its documented cap;
- rules are spread across the alphabet, with <5% `0.0.0.0` filler;
- no regex rules, >90% host-anchored;
- a real installed rule actually stops the browser;
- the popup never claims protection while zero rules are installed.

CI runs it as a separate job. Both projects now use distinct browser profiles — sharing one
leaked feed data and settings between them and produced two flaky failures that were
actually isolation bugs.

---

## 5. The finding that mattered before it: statistics built on a development-only API

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

Stated in the product itself, in `store/LIMITATIONS.md`.

**On ad blocking, measured rather than asserted.** Against the live EasyList and
EasyPrivacy: ~97,000 network rules compile against a 27,000-rule quota, so roughly 70% of
what those lists contain is not enforced. YouTube specifically is blocked only partially,
because the bulk of EasyList's YouTube rules are *cosmetic* — `##.video-ads`,
`###ytd-ad-slot-renderer` — and hiding elements is not something `declarativeNetRequest`
can express. The 2,500 ad rules that are installed do block the ad *networks* (DoubleClick,
AdNxs, Criteo, Taboola and similar), so scripts and images from those hosts are blocked,
but ad slots inside YouTube's own page will still render. Adding cosmetic filtering would
require `web_accessible_resources` to serve injected CSS, which trades away a deliberate
security property. That trade-off is a decision for the product owner, not a detail.

What was verified working: a rule compiled from a real feed entry stops the browser
before DNS is consulted, and no site is falsely blocked in the offline suite.

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
