# VOLTRIS Browser Shield — Privacy Policy

**Version 1.1.0 · Last updated: 2026-10-15**

VOLTRIS Browser Shield is a **local-first** browser extension. There is no account,
no server operated by VOLTRIS, and no telemetry. This document states exactly what
the extension stores, what it can observe, and what it deliberately never collects.

---

## 1. Summary

| Question | Answer |
|---|---|
| Do I need an account? | No. |
| Do you operate a server that receives my browsing data? | No. |
| Is there any analytics or telemetry? | No. |
| Does the extension send my URLs anywhere? | No. URLs are analysed entirely on your device. |
| Do you sell or share data? | No. There is nothing to sell. |
| What leaves my device? | Only threat-list files downloaded from the public sources listed in Settings → Updates. |

The "no data collection" answer given on the store listing forms is backed by an
automated audit of the **built package**, not by this document's promise. See
[§9 Verified evidence](#9-verified-evidence).

---

## 2. What is NEVER collected

The following are **never** read, stored or transmitted. This is enforced by an
automated test (`tests/unit/privacy-lint.test.ts`) that fails the build if any code
path attempts it:

- **Browsing history.** No history permission is requested and no history API is used.
- **Passwords and form contents.** The content script reads no input values. It inspects
  element *structure* (tag names, `type`, `placeholder`, `aria-label`) and nothing else.
  `input.value` does not appear anywhere in the codebase.
- **Authentication cookies and tokens.** No `cookies` permission is requested. The
  content script never touches `document.cookie`, `localStorage`, `sessionStorage` or
  `indexedDB`.
- **Page content sent anywhere.** No page content is transmitted. Analysis happens in
  the extension's own process and the result stays local.
- **Tracking identifiers.** No fingerprinting, no device identifiers, no unique IDs are
  created or stored.
- **2FA codes, banking data or private messages.** Never read.

---

## 3. What the extension CAN observe

The extension requests host access to all addresses (`<all_urls>`). This is strictly
necessary to evaluate URLs and to block requests. With that access the extension can:

- **Evaluate the address of the page you are on.** The hostname and path are analysed
  locally against a threat database and a set of heuristics.
- **Evaluate link destinations** when you hover a link, if the feature is enabled.
- **Inspect page structure** to detect scam patterns (fake browser updates, fake virus
  alerts, forced software installation prompts). It reads text nodes and element
  attributes; it does not read form values.
- **Observe download metadata**: file name, source page and URL, to warn about
  suspicious downloads.
- **Block requests** that match threat or privacy rules.
- **Notice that a navigation we blocked failed.** When a page you tried to open is
  stopped by one of our rules, the browser reports the failed navigation so the block
  can be counted and explained on the page you are shown. This event is used for that
  purpose only: the URL is checked against our own local threat data, and if we did
  not block it we neither record it nor display anything.

Everything above is computed on your device. The blocked-navigation event is never
stored as a full browsing record: only the registrable domain of a block we caused
enters the local counter and event history described in §4.

---

## 4. What is stored locally

All data is stored with `chrome.storage.local` on your device. Nothing is synchronised.

| Data | Purpose | Retention |
|---|---|---|
| Your settings | Remember your configuration | Until you change or clear it |
| Per-site exceptions | Remember which sites you allowed | Until you remove them |
| Block counters | Show how many pages we stopped | Until you clear them |
| Security event history | Show recent events on the dashboard | Capped at 300 events; domain only by default |
| Threat list data | Block known malicious destinations | Refreshed automatically; replaced wholesale |

**History stores the domain only** (for example `example.com`), never the path, query
string or fragment, unless you explicitly enable "Store full URLs". Even then, query
strings and fragments are stripped before storage.

**What the counters mean.** The dashboard shows blocked *pages* — top-level
navigations we observed being stopped — plus the number of filtering rules installed.
It does not show a per-request count, because the browser provides no way to measure
that in a published extension. The dashboard states this in the "What these numbers
mean" panel rather than displaying a number we cannot substantiate.

## 5. Network use

The extension performs outbound HTTPS requests **only** to download threat lists. The
exact providers, their licences and their URLs are shown in Settings → Updates and
listed in `store/FEEDS_AND_LICENSES.md`.

- Requests carry **no data about you, your browsing or your device**. Only the request
  for the public list file.
- Cookies and credentials are never sent with these requests (`credentials: 'omit'`,
  verified in the built package).
- Every request is a `GET` with no request body. No request identifies you.
- Two providers require an API key and are **disabled until you supply your own key**
  in Settings. When you do, your key is sent as an HTTP header **to that provider
  only**, for that provider's requests only. VOLTRIS never embeds a third-party key,
  and no credentialed provider is enabled by default.
- No provider is contacted without being listed in the interface.

No other outbound request exists. This is enforced by `scripts/privacy-audit.mjs` and
`scripts/static-analysis.mjs`, which both analyse the built package and fail the build
if an undeclared destination appears.

**What the feed providers can still see.** A list download is an ordinary HTTPS
request, so the provider receives the network information any web server receives,
including your IP address. This is unavoidable when downloading a file from the public
internet, it applies equally whether or not an extension is installed, and it is not
used to build a profile. No browsing data, hostname of the page you were on, or
referrer is included.

---

## 6. Third-party content

Threat lists are third-party data. They contain **domain names and URLs reported as
malicious by their communities**, not personal data about you. We do not control
their contents or update cadence.

Derived rule data compiled from EasyList is distributed under **CC BY-SA 3.0**; see
`THIRD_PARTY_NOTICES.md`.

---

## 7. Your controls

Settings → About and privacy provides:

- **Delete everything** — removes settings, statistics, exceptions, history and
  downloaded threat data from this device.
- Granular deletion of individual data categories.
- Switches to disable event history entirely, and to keep full URLs out of it.

---

## 8. Permissions and why each one exists

| Permission | Justification |
|---|---|
| `storage` | Save settings and statistics on your device. |
| `alarms` | Check for threat-list updates in the background. |
| `declarativeNetRequest` | Block requests without reading page content. |
| `webNavigation` | Notice when a page we block fails to load, so the block can be counted and explained instead of leaving you on a raw browser error page. |
| `downloads` | Warn about suspicious downloads. |
| `notifications` | Show download and update notifications. |
| `scripting` | Re-run the page analysis when you ask for it. |
| `<all_urls>` | Evaluate URLs and block requests. URLs stay on your device. |

No other permission is requested. The list is verified automatically by
`tests/unit/privacy-lint.test.ts` and `scripts/privacy-audit.mjs`.

**A note on `declarativeNetRequestFeedback`.** An earlier build requested this
permission to count blocks. Chrome documents it as enabling debugging features *for
unpacked extensions only*, so it would have granted nothing in a store install while
appearing to grant access. It has been removed, along with every dependency on it.
`webNavigation` replaced it. This is recorded here because a permission removed for
this reason can look, to a reviewer comparing versions, like a reduction in
functionality; the block counters and the explanation page both work, and are covered
by automated tests, without it.

---

## 9. Verified evidence

The claims in this document are checked against the built, publishable package by
`npm run audit:privacy`, which runs as part of `npm run verify`. It verifies that:

1. No permission granting access to stored user data is declared (no `cookies`,
   `history`, `bookmarks`, `topSites`, `webRequest`, `nativeMessaging`, `clipboard*`,
   `browsingData`, `desktopCapture`, `sessions`, `geolocation`, `proxy`, `debugger`…).
2. The only host permission is `<all_urls>`.
3. Every outbound host in the built JavaScript is a threat-feed host declared in the
   feed registry. Hosts that are XML namespace identifiers are listed and explained
   rather than silently ignored.
4. No analytics, telemetry or tracking host appears anywhere in the package.
5. Every `fetch` sets `credentials: 'omit'`, so no cookie can be attached.
6. No `fetch` carries a request body and none uses a non-`GET` method.
7. Any credential header is the user's own API key, sent only to the provider that
   issued it, and only when the user supplied it.
8. No local storage key holds passwords, cookies, tokens or page content.
9. No `externally_connectable` or `web_accessible_resources` surface exists.

**What this evidence does not cover.** It cannot show that your browser or operating
system records nothing of its own, and it cannot control what the feed publishers do
with the connection logs described in §5.

---

## 10. Children

The extension does not knowingly collect data from anyone, including children. Because
it collects no personal data at all, this is a property of the design rather than a
policy choice.

## 11. Changes

Material changes to this policy will be published with the extension update that
introduces them, and the version and date above will be updated.

## 12. Contact

Questions about this policy: **privacy@voltris.com**
