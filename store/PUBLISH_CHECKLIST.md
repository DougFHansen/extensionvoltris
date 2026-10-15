# Publication Checklist — VOLTRIS Browser Shield 1.1.0

Legend: `[x]` done · `[ ]` pending (requires your accounts / decisions)

---

## 1. Package integrity

- [x] Build produces `dist/chrome` and `dist/edge`
- [x] `dist/edge` omits `minimum_chrome_version` (a real Chrome-only manifest field)
- [x] Store archives generated: `artifacts/voltris-browser-shield-1.1.0-{chrome,edge}.zip`
- [x] SHA-256 checksums written to `artifacts/SHA256SUMS.txt`
- [x] Package size ~125 KiB (store limit is 2 GB)
- [x] Static analysis passes: CSP, permissions, no eval, no remote scripts, no inline scripts
- [x] TypeScript compiles with **zero** errors under `strict` + `noUncheckedIndexedAccess`

### Archive format (two submission blockers found and fixed)

- [x] **Path separators are `/`, never `\`.** PowerShell's `Compress-Archive` on Windows
      PowerShell 5.1 writes `\` inside the archive, which violates APPNOTE 4.4.17.1.
      The Chrome Web Store cannot read such a package. Replaced with a dependency-free
      ZIP writer (`scripts/lib/zip.mjs`).
- [x] **`manifest.json` sits at the archive root**, not inside a top-level folder.
- [x] No absolute paths, no `..` traversal, no directory entries.
- [x] `npm run verify:package` extracts the archive with **.NET, an independent reader**,
      then loads it into a real Chromium and opens the popup. A packaging defect fails
      here instead of during review.
- [x] `tests/unit/zip.test.ts` pins the separator rule, the CRC-32 vector, the
      end-of-central-directory record and byte-for-byte reproducibility.

### Store character limits (two more blockers found and fixed)

Chrome rejects an upload when these exceed their caps, and the error does not name the
field. `tests/unit/store-limits.test.ts` now enforces them in both locales.

- [x] `name` ≤ 45 characters — currently 22
- [x] `short_name` ≤ 12 characters — was **14** (`Browser Shield`), now `VOLTRIS` (7)
- [x] `description` ≤ 132 characters — was **198** (en) / **163** (pt-BR), now 127 / 126
- [x] No absolute security claim in the description (both stores reject "100% protected")

## 2. Manifest

- [x] Manifest V3, valid in Chrome 120+ and Edge 120+
- [x] `default_locale` set; `_locales/en` and `_locales/pt_BR` both present and key-identical
- [x] Name, short name and description localised via `__MSG_*__`
- [x] Icons 16/32/48/128 generated from source, no binary blobs checked in as opaque assets
- [x] Strict CSP: `script-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'`
- [x] No `externally_connectable`
- [x] **No `web_accessible_resources`** — no extension page is reachable by a website
- [x] Permissions limited to 7 + `<all_urls>`, each justified in the Diagnostics tab
- [x] **No development-only permission.** `declarativeNetRequestFeedback` was removed in
      1.1.0. It gates `onRuleMatchedDebug`, which Chrome documents as unpacked-only, so it
      granted nothing in a store install. `webNavigation` replaced it and provides the
      same two capabilities (block counting and the explanation page) in production.
- [x] If a reviewer compares versions: `webNavigation` was **added** and
      `declarativeNetRequestFeedback` **removed**. Both are ordinary, warning-free
      permissions. The justification text is in the extension's own Permissions tab and in
      `PRIVACY.md` §8.

## 3. Legal and policy documents

- [x] `PRIVACY.md` — store-compliant, plain language, states what is never collected
- [x] `THIRD_PARTY_NOTICES.md` — licences and attribution, including the CC BY-SA election
- [x] `store/FEEDS_AND_LICENSES.md` — per-provider source, licence, verification date
- [x] `store/LIMITATIONS.md` — honest limitations, no absolute-security claims
- [x] `store/THREAT_MODEL.md`
- [x] Trademark note included
- [ ] **You:** confirm the `VOLTRIS` trademark and the `privacy@voltris.com` address
- [ ] **You:** re-verify the feed licences at submission time (they were verified 2026-10-13)

## 4. Store listing assets

- [x] Short description (≤132 chars) in `src/_locales/*/messages.json`
- [x] Long description
- [x] Category: Privacy / Security (single, clear central purpose)
- [ ] **You:** produce store screenshots (1280×800 or 640×400). Capture list:
      1. Popup — protection status + current-site verdict
      2. Dashboard — security summary + 14-day chart
      3. Settings — Updates tab showing provider licences and status
      4. Blocked page — explanation with source and reason
      5. Privacy tab — what is never collected
- [ ] **You:** upload a 128×128 promotional tile if required

## 5. Chrome Web Store submission

- [ ] **You:** host `PRIVACY.md` at a public HTTPS URL. Both stores require a **URL**,
      not pasted text alone. GitHub Pages is sufficient and free. The file must be
      reachable without a login. Keep the URL stable — changing it requires re-review.
- [ ] **You:** create the developer account (US$5 one-time, Google developer account
      required). Unverified accounts can publish; verified ones get a faster review.
- [ ] **You:** upload `artifacts/voltris-browser-shield-1.1.0-chrome.zip`
- [ ] **You:** paste the privacy policy URL in "Privacy practices"
- [ ] **You:** declare data collection = **None**. Answer "no" to every data category;
      do not tick "website content" or "browsing activity" — none is transmitted.
- [ ] **You:** justify `<all_urls>` host access
- [ ] **You:** complete the single-purpose justification: *navigation protection and privacy*
- [ ] **You:** confirm no OAuth / no remote code (both true; both are asked)
- [ ] **You:** set the category to a single value. Pick **Privacy** or **Security** —
      listing under both is a common rejection reason.
- [ ] **You:** set "Users" / "Language" to **English (US)** and **Portuguese (Brazil)**

## 6. Microsoft Edge Add-ons submission

- [ ] **You:** create a Partner Center account (free; a Microsoft account is required)
- [ ] **You:** upload `artifacts/voltris-browser-shield-1.1.0-edge.zip`
- [ ] **You:** supply the **same** privacy policy URL
- [ ] **You:** declare no data collection
- [ ] **You:** link the Chrome Web Store listing if it exists yet (optional, and it
      accelerates Edge certification)

## 7. Pre-submission verification (run before uploading)

```powershell
npm ci
npm run verify          # typecheck + unit tests + build + static audit + privacy audit + package
npm run test:e2e        # loads the built extension into a real Chromium
npm run verify:package  # loads the PACKAGED zip into a real Chromium
npm audit --audit-level=high
```

Expected: 312+ unit tests pass, 28 end-to-end tests pass, both audits clean,
`npm run verify:package` reports "packaged archive loads and runs",
`npm audit` reports no high or critical advisories.

Run this immediately before you upload. If you change any string in
`src/_locales/`, `src/manifest.json` or the build config, the package must be
regenerated — the archives are what the stores receive, not `dist/`.

## 8. Known items to mention in a review response

If a reviewer asks, these are the honest answers:

- **"Why `<all_urls>`?"** — Required to evaluate URLs and to block requests. URLs are
  analysed locally and never transmitted. Documented in the Diagnostics tab.
- **"Do you collect data?"** — No. No telemetry, no analytics, no account, no server.
  The only outbound requests are threat-list downloads, listed in Settings ▸ Updates.
  `npm run audit:privacy` proves this against the built package and prints per-claim
  evidence; `PRIVACY.md` §9 lists exactly what it verifies.
- **"Why does it need `webNavigation`?"** — To notice that a page we blocked failed to
  load, so the block can be counted and explained instead of leaving the user on a raw
  browser error page. It is an ordinary permission and shows no install-time warning.
- **"An earlier version requested `declarativeNetRequestFeedback`. Why was it removed?"**
  — Because Chrome documents that permission as enabling debugging features *for unpacked
  extensions only*. It granted nothing in a store install while making the extension
  appear to gather access it did not have. Removing it fixed a real fault: in 1.0.0 the
  block counters read zero and the explanation page never appeared once published.
  `webNavigation` provides both capabilities in production, and the end-to-end suite runs
  with the debug API absent so this is verified rather than asserted.
- **"How many block counters do you show?"** — Blocked *pages*, plus the installed rule
  count, detections and download warnings. Per-request sub-resource blocking cannot be
  measured in a published extension, so the dashboard labels that metric as not
  measurable instead of showing a zero. We would rather show no number than one we cannot
  substantiate.
- **"Can I trust the threat sources?"** — Every provider's licence and source is shown
  in Settings ▸ Updates, with two providers deliberately excluded because their terms
  forbid commercial use.

## 9. Post-release

- [ ] Monitor feed update failures in Diagnostics for the first week
- [ ] Re-run `npm run psl -- --update` monthly (Public Suffix List changes)
- [ ] Re-verify feed licences quarterly
