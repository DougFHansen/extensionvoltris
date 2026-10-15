/**
 * VOLTRIS Browser Shield - content script (ISOLATED world).
 *
 * Responsibilities:
 *  1. Run the page scam scan once at `document_idle`.
 *  2. Offer a discreet hover warning for links whose destination carries
 *     relevant risk.
 *
 * Hard constraints:
 *  - Isolated world only; the page cannot see or tamper with our state.
 *  - No `.value`, no cookies, no storage, no tokens (see privacy lint test).
 *  - No permanent MutationObserver. Hover handling is delegated and throttled.
 *  - Hover warnings are OFF by default in terms of DOM mutation: we show a
 *    native `title`-like tooltip only through a single, reused node that is
 *    created on first use and removed when idle.
 */
import { SCAM_SCAN_FUNCTION } from '../scam/scam-scan-source';

const HOVER_THROTTLE_MS = 250;
const TOOLTIP_ID = 'vbs-link-tooltip';
const TOOLTIP_HIDE_MS = 2_600;

interface HoverVerdict {
  readonly verdict: string;
  readonly hostname: string | null;
  readonly label: string;
}

let lastHoverAt = 0;
let tooltip: HTMLElement | null = null;
let hideTimer: ReturnType<typeof setTimeout> | null = null;

function message<T>(t: string, p?: unknown): Promise<{ ok: boolean; data?: T } | null> {
  return new Promise((resolve) => {
    try {
      chrome.runtime
        .sendMessage({ v: 1, t, p })
        .then((response) => resolve(response as { ok: boolean; data?: T } | null))
        .catch(() => resolve(null));
    } catch {
      resolve(null);
    }
  });
}

function ensureTooltip(): HTMLElement | null {
  if (tooltip && tooltip.isConnected) return tooltip;
  if (!document.body) return null;
  const host = document.createElement('div');
  host.id = TOOLTIP_ID;
  // Styling is applied via inline styles because extension CSS is not injected
  // into arbitrary pages, and inline styles on OUR OWN element cannot be used
  // for script execution (CSP-safe).
  host.style.cssText = [
    'position:fixed',
    'z-index:2147483647',
    'max-width:320px',
    'padding:8px 10px',
    'border-radius:8px',
    'font:12px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif',
    'pointer-events:none',
    'box-shadow:0 8px 24px rgba(0,0,0,.28)',
    'display:none',
  ].join(';');
  document.body.appendChild(host);
  tooltip = host;
  return tooltip;
}

function showTooltip(anchor: HTMLElement, verdict: HoverVerdict): void {
  const node = ensureTooltip();
  if (!node) return;

  // textContent only. The label comes from our own i18n via the service worker.
  node.textContent = verdict.label;
  const danger = verdict.verdict === 'known-malicious' || verdict.verdict === 'suspicious';
  node.style.background = danger ? '#7f1d1d' : '#1f2937';
  node.style.color = '#ffffff';
  node.style.display = 'block';

  const rect = anchor.getBoundingClientRect();
  const top = rect.bottom + 6;
  const left = Math.max(8, Math.min(rect.left, window.innerWidth - 336));
  node.style.top = `${Math.min(top, window.innerHeight - 60)}px`;
  node.style.left = `${left}px`;

  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = setTimeout(hideTooltip, TOOLTIP_HIDE_MS);
}

function hideTooltip(): void {
  if (tooltip) tooltip.style.display = 'none';
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
}

let settingsCache: { showHoverWarnings: boolean; protectionEnabled: boolean; scamPageAnalysis: boolean } | null = null;

async function loadSettings(): Promise<typeof settingsCache> {
  if (settingsCache) return settingsCache;
  const response = await message<Record<string, boolean>>('settings.get', {});
  if (response && response.ok && response.data) {
    settingsCache = {
      showHoverWarnings: response.data.showHoverWarnings === true,
      protectionEnabled: response.data.protectionEnabled === true,
      scamPageAnalysis: response.data.scamPageAnalysis === true,
    };
  } else {
    settingsCache = { showHoverWarnings: true, protectionEnabled: true, scamPageAnalysis: true };
  }
  return settingsCache;
}

chrome.storage?.onChanged?.addListener?.((changes, areaName) => {
  if (areaName !== 'local') return;
  if ('vbs.settings' in changes) settingsCache = null;
});

function onMouseOver(event: MouseEvent): void {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const anchor = target.closest('a[href]');
  if (!(anchor instanceof HTMLAnchorElement)) {
    hideTooltip();
    return;
  }

  const href = anchor.getAttribute('href') ?? '';
  if (href.length === 0 || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) {
    hideTooltip();
    return;
  }

  const now = Date.now();
  if (now - lastHoverAt < HOVER_THROTTLE_MS) return;
  lastHoverAt = now;

  void (async () => {
    const settings = await loadSettings();
    if (!settings || !settings.showHoverWarnings || !settings.protectionEnabled) return;

    let absolute: string;
    try {
      absolute = new URL(anchor.href, window.location.href).toString();
    } catch {
      return;
    }

    const response = await message<{ result: { verdict: string; hostname: string | null; reasons: { code: string }[] } }>(
      'content.linkInspect',
      { url: absolute },
    );
    if (!response || !response.ok || !response.data) return;

    const result = response.data.result;
    if (result.verdict !== 'known-malicious' && result.verdict !== 'suspicious') return;

    const label =
      result.verdict === 'known-malicious'
        ? chrome.i18n.getMessage('hover_known_malicious')
        : chrome.i18n.getMessage('hover_suspicious');

    showTooltip(anchor, { verdict: result.verdict, hostname: result.hostname, label });
  })();
}

function start(): void {
  void (async () => {
    const settings = await loadSettings();
    if (settings?.scamPageAnalysis) SCAM_SCAN_FUNCTION();
    if (settings?.showHoverWarnings && settings?.protectionEnabled) {
      // Delegated listener on the document: one listener, not one per node.
      document.addEventListener('mouseover', onMouseOver, { passive: true, capture: true });
      document.addEventListener('mouseout', hideTooltip, { passive: true, capture: true });
      window.addEventListener('scroll', hideTooltip, { passive: true, capture: true });
    }
  })();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
