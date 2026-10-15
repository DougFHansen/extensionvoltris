# Known Limitations — Stated Plainly

This document exists because honest limits build more trust than bold claims.
Everything here is a real, current limitation of version 1.0.0. Nothing on this list
is simulated, stubbed or "coming soon in this build".

---

## 1. Detection coverage

- **The extension cannot detect every malicious site.** Threat feeds only contain URLs
  that have already been reported by someone. A site that has never been reported is
  invisible to a reputation engine, by definition.

### Ad and tracker blocking is partial — measured, not estimated

Chrome caps an extension at **30,000 declarative network rules**, of which we can use
27,000. Measured against the live lists:

| Data | Available | Installable | Coverage |
|---|---|---|---|
| Phishing.Database active domains | 386,074 | 13,000 | **3.4%** |
| EasyList network rules (ads) | 50,327 | 2,500 | **5.0%** |
| EasyPrivacy network rules | 47,235 | 3,500 | 7.4% |

**A 5% sample cannot contain any particular ad network.** Every major ad host
(`static.doubleclick.net`, `pagead2.googlesyndication.com`, `taboola.com`, `adnxs.com`)
is listed in EasyList and none of them is installed. This is arithmetic, not a bug: no
sampling strategy produces useful ad blocking at 5% coverage.

- **YouTube ads are therefore not blocked.** Most of EasyList's YouTube rules are
  *cosmetic* filters (`##.video-ads`, `###ytd-ad-slot-renderer`) that hide elements inside
  the page. `declarativeNetRequest` cannot hide page elements, and Chrome's
  `declarativeContent` API offers only `showAction` and `setIcon` — no CSS injection. There
  is no MV3-native way to do cosmetic filtering.
- **The only route is serving injected CSS**, which requires declaring
  `web_accessible_resources`. This project deliberately has none. That trade-off has not
  been taken; it is a product decision.
- **A curated priority list of major ad networks** would fit in the budget (a few hundred
  domains) and would block the big networks. It has not been added because it means
  hand-maintaining a list that could drift out of date, and a wrong entry breaks a site
  for the user.
- **Blocking is verified, not assumed.** The end-to-end suite downloads the real feeds,
  reads the installed rule set back out of the browser, confirms a rule compiled from a
  real feed entry stops a navigation, and asserts the retained rules span the whole
  alphabet. That last check exists because an earlier build sampled the lists and *then*
  took a sorted prefix, which cancelled itself out and left thousands of rules covering
  only domains beginning with `0` and `a`.
- **Freshly registered domains and zero-days are not covered.** This is the expected
  behaviour of every feed-based blocker. The heuristic engine raises the probability of
  catching new campaigns; it does not eliminate the gap.
- **`No threat identified` does not mean safe.** It means we found no evidence in the
  data we hold. The interface says exactly that.
- **Feeds are eventually consistent.** A newly reported malicious site may take hours
  to appear, and may never appear if it is short-lived.

## 2. Redirects

- **Server-side redirects are not observable in advance.** With the permissions we
  request, there is no supported way to see a 302 target before the browser follows it.
  We analyse the destination that is actually reached. The `redirect_to_threat` signal
  exists in the engine and is unit-tested, but it is **not** wired to a live redirect
  API in this version, because adding one would require an extra permission with a
  user-visible warning for a capability Manifest V3 does not otherwise offer.
- **URL shorteners are not expanded automatically.** Expanding them would either fetch
  a third-party destination driven by page content, or send browsing data to a
  resolution service — both contradict the privacy design. Shorteners are reported as
  an informational signal so you know the real destination is hidden.

## 3. Page analysis limits

- **We cannot prove a page is lying.** There is no certificate-history API, no
  brand-verification service and no server reputation query available to an extension.
  Page signals describe what a page *claims* and *looks like*; they are presented as
  warnings with their evidence, never as proof.
- **Page signals never block a site on their own.** They contribute to the risk score
  and can raise a site to `suspicious`, but a block always requires a verified feed
  match.
- **Content scripts run in the main frame only** (`all_frames: false`). Scam analysis
  does not run inside iframes.

## 4. Downloads

- **File contents are never inspected.** No extension API provides safe access to a
  downloaded file's bytes, and we do not attempt it.
- **This is not an antivirus.** It does not replace Chrome/Edge download checks,
  SmartScreen or Defender, and it never disables them.
- **Cancellation is offered only at high confidence** and only when you choose the
  "Cancel" action. The default is **alert only**, because a legitimate installer with
  a `.exe` extension must not be punished for its extension.
- **A `.exe`, `.msi` or `.zip` is never blocked on that basis alone.** Only a double
  extension combined with high-confidence evidence, or a known-malicious source,
  triggers a warning.

## 5. Blocking and the browser rule limit

- **Chrome and Edge cap dynamic rules at 30,000** (and 5,000 for "unsafe" rules). Our
  dataset is larger than that. Rules are therefore prioritised — malware and phishing
  first, trackers and ads last — and the remainder is dropped.
- **We report every drop.** Settings → Diagnostics shows "Dropped for quota" and names
  the affected categories. A truncated list is never presented as complete.
- **Cosmetic filtering is not supported.** Adblock "element hiding" rules (`##.ad`) are
  counted and reported but cannot be converted to a network rule. Ads are blocked at the
  request level, so some cosmetic gaps remain on sites that rely on hiding.

## 6. Privacy

- **Host access to all addresses is required** to evaluate URLs and block requests.
  Chrome will display "Read and change all your data on all websites". URLs are
  analysed locally and are never sent anywhere.
- **The event history stores domains.** Full URLs are opt-in, and query strings and
  fragments are stripped either way.

## 7. Integrations we do not have

These are registered in the interface and reported as unavailable. **No result is
simulated for them.**

| Integration | Status | Reason |
|---|---|---|
| URLhaus (abuse.ch) | **Excluded** | Requires an Auth-Key; commercial use may require a paid subscription (verified at urlhaus.abuse.ch/api). |
| OpenPhish | **Excluded** | Terms of Use prohibit commercial use, explicitly including "product development" and "customer protection". |
| PhishTank | **Not configured** | Requires your own free app key. We never embed a third-party key. |
| VirusTotal / commercial reputation APIs | **Not integrated** | Require paid infrastructure we do not operate. |

## 8. Signature verification

- **None of the bundled feeds publish per-file cryptographic signatures.** We compute
  and display a SHA-256 of each validated payload, and we vendor the Public Suffix List
  with its hash for reproducibility, but we do **not** claim signature verification.
  Claiming it would be false.

## 9. Browser support

- **Chrome 120+ and Edge 120+.** The 30,000 safe dynamic-rule allowance depends on
  Chrome 121+; on older versions the extension falls back to the conservative 5,000
  budget automatically and reports it in Diagnostics.
- **The explanatory block page depends on `webNavigation.onErrorOccurred`.** If a future
  browser removes it, blocking still works but the user sees the browser's error page
  instead of our explanation, and blocked-page counters stop advancing. Diagnostics
  reports `observation.apiAvailable`.
- **Per-request block counts are not available in a published extension.** The browser
  exposes matched-rule events only to unpacked, development builds, so we cannot count
  blocked images, scripts or trackers on a user's machine. The dashboard reports
  blocked *pages* and the installed rule count, and explicitly labels the sub-resource
  metric as not measurable. We show no number rather than an invented one.
- **MV3 service workers are suspended by the browser.** This is by design and handled:
  all state is persisted, and the worker rebuilds its rule set on wake. This is covered
  by an automated test.

## 9b. What our tests do and do not prove

- The E2E suite runs against the extension **loaded unpacked**, because that is the only
  way to automate an extension. Every test that depends on a production-only API
  assumption is written against the *shipped* permission set — the debug feedback
  permission is not requested, so the suite exercises the same configuration a store
  install receives. A test asserts this explicitly rather than assuming it.
- We have **not** published the extension to the Chrome Web Store or Edge Add-ons and
  observed it installed from a store. Claims about store-install behaviour rest on
  Chrome's own API documentation and on the test above, not on a store trial.

## 10. Testing scope

- **Our tests prove our logic, not the real-world efficacy of a feed.** A passing test
  suite means the extension correctly parses, scores, blocks and explains what it was
  given. It does **not** mean the shipped lists are complete or current.
- **End-to-end tests never visit a real malicious site.** Every hostile target in the
  suite is an RFC 2606 reserved name (`.test`) that never resolves, served or
  synthesised locally.
- **Chromium service workers were never observed suspended within the 45-second
  observation window on the reference machine** (Chromium keeps the worker alive while
  attached). The test asserts the guarantee that matters — the first interaction after
  an idle period is fully correct — and reports the observation separately.
