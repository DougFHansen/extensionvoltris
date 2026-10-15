# Installing VOLTRIS Browser Shield

## Requirements

- Google Chrome **120+**, or Microsoft Edge **120+**
- About 500 KB of disk space
- No account, no sign-in

---

## A. Load the unpacked extension (recommended for evaluation)

### Google Chrome

1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the folder `dist/chrome`

### Microsoft Edge

1. Open `edge://extensions`
2. Turn on **Developer mode** (left sidebar, bottom)
3. Click **Load unpacked**
4. Select the folder `dist/edge`

After loading, the toolbar should show the VOLTRIS shield. Pin it (right-click the
extension in the menu → **Pin**).

> If you change the source, re-run `npm run build` and press **Reload** on the
> extensions page. Chrome keeps the previous rule set; reloading re-applies it.

---

## B. Install the packaged archive

Store packages are ZIP files that contain the extension at the **root** of the archive.

- **Chrome / Edge (unpacked for review):** extract the ZIP to a folder and use "Load
  unpacked" as above.
- **Chrome Web Store:** upload `artifacts/voltris-browser-shield-<version>-chrome.zip`.
- **Edge Add-ons:** upload `artifacts/voltris-browser-shield-<version>-edge.zip`.

Verify the download before installing:

```powershell
Get-Content artifacts\SHA256SUMS.txt
Get-FileHash artifacts\voltris-browser-shield-1.0.0-chrome.zip -Algorithm SHA256
```

---

## C. First run

1. Open the popup. You should see **Protection active**.
2. The first background update downloads threat lists. Watch progress in
   **Settings → Updates**. This takes a few seconds and happens once.
3. Optionally open **Settings → Sites** and add a site if protection interferes with
   a page you trust. Choose the **narrowest** scope that works — see below.

---

## Allowlist scopes — pick the narrowest one

| Scope | What it stops | Use when |
|---|---|---|
| **Ads and trackers only** (recommended) | Tracker/ad blocking for this site | A site breaks because of privacy filtering. Malware and phishing blocking stay on. |
| **Phishing and malware requests** | Sub-resource requests to that domain | Rare. The site itself stays blocked for top-level navigation. |
| **Disable all protection** | Everything, including malware | Only when you are certain the detection is wrong. |

You can widen or narrow an entry at any time in **Settings → Sites**.

---

## Uninstall

**Chrome:** `chrome://extensions` → VOLTRIS Browser Shield → **Remove**.
**Edge:** `edge://extensions` → VOLTRIS Browser Shield → left menu → **Remove**.

Removing the extension deletes its local data. You can also delete data without
uninstalling via **Settings → About and privacy → Delete everything**.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Popup shows "Protection paused" | Master switch off | Toggle **Protection** in the popup |
| Nothing seems blocked | Threat lists not downloaded yet | **Settings → Updates → Update now**; check Diagnostics for errors |
| A site is blocked and you trust it | It matched a rule | **Settings → Sites** → add the domain with the narrowest scope |
| "List truncated to fit the browser rule limit" | Feed larger than Chrome's rule quota | Expected; Diagnostics lists exactly which categories were affected |
| Extension icon missing | Not pinned | Right-click the extensions menu → pin |
| Service worker shows as inactive | Normal for Manifest V3 | It wakes on the next event; nothing to do |

**Diagnostics** (Settings → Diagnostics) reports: browser rule limits, installed rule
count, quota drops, which listeners registered, storage usage, Public Suffix List
status, and the integration status of every provider — including the ones that are
deliberately not configured.

---

## Uninstall / upgrade notes

- Installing a new version over an existing install keeps your settings.
- The threat dataset is replaced atomically; a failed update never leaves you without
  protection.
