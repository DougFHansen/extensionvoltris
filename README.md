# VOLTRIS Browser Shield

Local-first browser security extension for **Google Chrome** and **Microsoft Edge**
(Manifest V3). Multi-layer URL analysis, threat blocking, scam detection, tracker and
ad filtering, download warnings and a private dashboard.

**No account. No telemetry. No server. URLs never leave your device.**

---

## What it does

| Capability | Detail |
|---|---|
| **Phishing / malware blocking** | Verified threat feeds compiled to `declarativeNetRequest` rules, with per-category priority so malware always outranks ads |
| **Multi-layer URL analysis** | Feed reputation, Unicode homographs, mixed scripts, bidi controls, brand impersonation, URL structure, shorteners |
| **Explainable verdicts** | `Known malicious` / `Suspicious` / `No threat identified` / `Not analysed`, each with its reasons, sources and dates |
| **Explanatory block page** | Domain, threat type, reason, source, date — and a two-step, risk-acknowledged override |
| **Tracker and ad filtering** | EasyList / EasyPrivacy converted through a conservative, audited parser |
| **Download warnings** | Double extensions, executable types, known-malicious sources — with the real confidence stated |
| **Scam page signals** | Fake updates, fake virus alerts, forced installs — structure only, never form values |
| **Link inspection** | Discreet warning on hover when a destination carries relevant risk |
| **Privacy dashboard** | What was blocked, when, by which category — all local, fully erasable |
| **Interface** | Premium, responsive, dark/light, keyboard-navigable, **PT-BR and EN** |

## What it does *not* claim

It cannot detect every malicious site, does not scan file contents, cannot predict
server-side redirects, and does not promise absolute safety. The full list is in
[`store/LIMITATIONS.md`](store/LIMITATIONS.md) — and in the app itself, because honest
limits build more trust than bold claims.

---

## Install

Unpacked (evaluation):

```
npm run build
```

- Chrome ▸ `chrome://extensions` ▸ Developer mode ▸ **Load unpacked** ▸ `dist/chrome`
- Edge ▸ `edge://extensions` ▸ Developer mode ▸ **Load unpacked** ▸ `dist/edge`

Full instructions: [`store/INSTALL.md`](store/INSTALL.md)

---

## Development

```bash
npm ci
npm run psl -- --update     # refresh the vendored Public Suffix List
npm run build               # generate PSL + icons, then bundle both targets
npm test                    # unit + integration (vitest)
npm run test:e2e            # loads the built extension into a real Chromium
npm run typecheck           # tsc --noEmit, strict
npm run audit:static        # analysis of the BUILT package
npm run verify              # everything above, then package
```

### Layout

```
src/
  core/          domain model, verified constants, shared types
  platform/      storage, messaging protocol, DNR wrapper
  data/          settings, stats, history, allowlist (all validated on read)
  security/      URL normalization, PSL, Unicode, heuristics, risk engine, downloads
  feeds/         provider registry, parsers, atomic update engine
  blocking/      rule compiler, quota manager, dataset assembly
  scam/          content-script scanner and signal validation
  background/    service worker: listeners, routing, rules, interstitial
  content/       isolated-world link inspector + one-shot page scan
  ui/            popup, dashboard, settings, block page, shared design system
scripts/         build, PSL generation, icons, packaging, static analysis, i18n
tests/unit/      280 tests: engine, parsers, quota, privacy lint, messaging, i18n
tests/e2e/       28 tests in a real Chromium with the extension loaded
store/           feeds & licences, limitations, threat model, install, checklist
```

---

## Design decisions worth knowing

**Block observation uses `webNavigation`, not the matched-rule feed.**
`declarativeNetRequest.onRuleMatchedDebug` is documented as available only to unpacked
extensions, so counting matched rules would make every counter read zero after a store
install — and the explanatory block page would never appear. The extension instead
listens to `webNavigation.onErrorOccurred`, keeps only main-frame
`net::ERR_BLOCKED_BY_CLIENT` failures, and **verifies the block was ours** by resolving
the destination against our own local threat dataset. Blocks caused by another
extension are neither counted nor claimed. Sub-resource blocks (images, scripts,
trackers) cannot be measured in a published build at all, and the dashboard says so
instead of showing a false zero.

**Rule ids encode their category.** `id = 100,000,000 × ordinal + n`. Production
attribution uses the threat dataset rather than the id, but a self-describing id keeps
the installed rule set debuggable and keeps `categoryFromRuleId` working with zero
storage lookups, including across worker restarts.

**Explicit priorities, not source ordering.** Chrome documents the tie-break order
(`allow > block > upgradeScheme > redirect`) but does **not** document how static,
dynamic and session rules interleave, and Edge may differ. Each logical band therefore
carries an explicit `priority`, making behaviour deterministic in both browsers.

**No `regexFilter`, anywhere.** Regex rules fall into the "unsafe" 5,000-rule bucket
and a separate 1,000-rule regex quota. Staying regex-free keeps every rule in the
30,000 safe bucket and removes a whole class of ReDoS exposure. Unsupported adblock
filters are counted and reported instead of approximated.

**The block page is not web-accessible.** `redirect.extensionPath` cannot carry
per-request data, and the only ways to inject it would be a regex rule or reflecting an
untrusted URL into a page other sites could load. Instead the DNR rule blocks the
navigation, the worker records it under an opaque token in `chrome.storage.session`, and
the worker drives the tab to our own page. No `web_accessible_resources` is needed at
all — no website can load or frame our pages.

**Scoped allowlist.** An ad exception must never disable malware protection, so the
three scopes sit in different priority bands: `privacy` sits *below* the malware/phicing
blocks, `threats` sits *above* them but still blocks top-level navigation to the site,
and `all` uses `allowAllRequests`. This is locked in by unit tests.

**Allowlisting changes what we do, not what we know.** A site listed in a verified feed
still reports `Known malicious` when allowlisted, because facts do not change because
you made an exception — the interface shows both. Silently downgrading the verdict would
be a lie you could act on.

**Privacy promises are tests, not prose.** `tests/unit/privacy-lint.test.ts` fails the
build if any code reads `.value`, `document.cookie`, web storage, `indexedDB`, the
clipboard, uses `innerHTML`/`eval`, or requests a high-risk permission. A Playwright
test types a password into a fixture page and asserts the value never appears in
extension storage.

**Defensive listener registration.** A missing permission makes an API `undefined`,
and the resulting `TypeError` silently killed every listener registered after it. Each
API is now probed individually and Diagnostics reports which ones registered.

---

## Documentation

| Document | Purpose |
|---|---|
| [`PRIVACY.md`](PRIVACY.md) | Store-compliant privacy policy |
| [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | Licences and attribution |
| [`store/FEEDS_AND_LICENSES.md`](store/FEEDS_AND_LICENSES.md) | Every provider: source, licence, verification date, decision |
| [`store/LIMITATIONS.md`](store/LIMITATIONS.md) | What it cannot do |
| [`store/THREAT_MODEL.md`](store/THREAT_MODEL.md) | Assets, boundaries, threats, mitigations |
| [`store/INSTALL.md`](store/INSTALL.md) | Installation and troubleshooting |
| [`store/PUBLISH_CHECKLIST.md`](store/PUBLISH_CHECKLIST.md) | Store submission checklist |

---

## Licence

Extension source code: proprietary, © 2026 VOLTRIS.
Derived rule data from EasyList: CC BY-SA 3.0 — see `THIRD_PARTY_NOTICES.md`.
