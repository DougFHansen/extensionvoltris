/**
 * Blocked-navigation page.
 *
 * TRUST MODEL (important):
 *  - The only thing read from `location.search` is an OPAQUE TOKEN.
 *  - The token is resolved to a record in `chrome.storage.session` and the
 *    verdict is RE-COMPUTED by the service worker from the recorded URL.
 *  - Nothing that arrives in the query string is rendered, trusted or used as a
 *    verdict. This page does not even read `location.href`.
 *  - All rendering goes through `textContent` (see `shared/components.ts`).
 */
import type { AnalysisResult } from '../../core/types';
import { request } from '../../platform/messages';
import type { BlockDetails } from '../../background/messages';
import {
  append,
  applyTheme,
  badge,
  button,
  clear,
  el,
  errorBox,
  formatDateTime,
  formatNumber,
  logo,
  spinner,
  t,
  toggle,
} from '../shared/components';
import { getSettings } from '../../data/settings';

const root = document.getElementById('app');

function readToken(): string | null {
  try {
    const token = new URLSearchParams(window.location.search).get('id');
    return token !== null && /^[0-9a-f]{32}[a-z0-9]{1,4}$/.test(token) ? token : null;
  } catch {
    return null;
  }
}

function categoryKey(category: string | null): string {
  return `category_${category ?? 'unknown'}`;
}

function reasonText(code: string): string {
  return t(`reason_${code.replace(/\./g, '_')}`);
}

function verdictTone(verdict: AnalysisResult['verdict'] | undefined): 'danger' | 'warn' | 'ok' | 'neutral' {
  switch (verdict) {
    case 'known-malicious':
      return 'danger';
    case 'suspicious':
      return 'warn';
    case 'no-threat-found':
      return 'ok';
    default:
      return 'neutral';
  }
}

function verdictKey(verdict: AnalysisResult['verdict'] | undefined): string {
  switch (verdict) {
    case 'known-malicious':
      return 'verdict_known_malicious';
    case 'suspicious':
      return 'verdict_suspicious';
    case 'no-threat-found':
      return 'verdict_no_threat_found';
    default:
      return 'verdict_not_analyzed';
  }
}

async function render(): Promise<void> {
  if (!root) return;
  clear(root);
  append(root, el('div', { class: 'popup-loading' }, [spinner(t('common_loading'))]));

  const settings = await getSettings().catch(() => null);
  if (settings) applyTheme(settings.theme, settings.reducedMotion);

  const token = readToken();
  if (token === null) {
    clear(root);
    append(root, buildShell(null));
    return;
  }

  const response = await request<BlockDetails>('blocked.details', { token });
  clear(root);

  if (!response.ok) {
    append(root, buildShell(null));
    return;
  }
  append(root, buildShell(response.data));
}

function buildShell(details: BlockDetails | null): HTMLElement {
  const analysis = details?.analysis ?? null;

  const head = el('header', { class: 'blocked-head' }, [
    el('div', { class: 'blocked-head-icon' }, [shieldGlyphLarge()]),
    el('div', { class: 'blocked-head-text' }, [
      el('h1', { text: t('blocked_title') }),
      el('p', { text: t('extension_name') }),
    ]),
    badge(t(verdictKey(analysis?.verdict)), verdictTone(analysis?.verdict)),
  ]);

  const body = el('div', { class: 'blocked-body' });
  if (details !== null && !details.found) {
    body.appendChild(errorBox(t('blocked_no_details')));
  }
  body.appendChild(renderTarget(details));
  body.appendChild(renderReasons(analysis));
  const provenance = renderProvenance(details, analysis);
  if (provenance) body.appendChild(provenance);
  body.appendChild(renderActions(details));
  const advanced = renderAdvanced(details);
  if (advanced) body.appendChild(advanced);

  const card = el('section', { class: 'blocked-card' }, [head, body]);
  return el('div', { class: 'blocked-shell' }, [
    el('div', { class: 'blocked-brand' }, [logo(20), el('span', { text: t('extension_name') })]),
    card,
    el('p', { class: 'blocked-note', text: t('blocked_reports_no_content_scan') }),
  ]);
}

function renderTarget(details: BlockDetails | null): HTMLElement {
  const hostname = details?.hostname ?? '';
  return el('div', { class: 'blocked-target' }, [
    el('span', { class: 'blocked-target-icon', 'aria-hidden': 'true', text: '#' }),
    el('div', { class: 'blocked-target-text' }, [
      el('small', { text: t('blocked_domain') }),
      el('strong', { text: hostname.length > 0 ? hostname : t('common_unknown') }),
    ]),
  ]);
}

function renderReasons(analysis: AnalysisResult | null): HTMLElement {
  const reasons = (analysis?.reasons ?? []).filter((r) => r.weight > 0).slice(0, 6);
  const section = el('section', { class: 'blocked-section' }, [el('h2', { text: t('blocked_reason') })]);

  if (reasons.length === 0) {
    section.appendChild(el('p', { class: 'muted small', text: t('blocked_no_details') }));
    return section;
  }

  section.appendChild(
    el(
      'div',
      {},
      reasons.map((reason) =>
        el('div', { class: 'blocked-reason' }, [
          el('span', { class: `blocked-reason-dot ${reason.severity}`, 'aria-hidden': 'true' }),
          el('span', { class: 'blocked-reason-text' }, [
            el('span', { text: reasonText(reason.code) }),
            evidenceLine(reason.data),
          ]),
        ]),
      ),
    ),
  );
  return section;
}

function evidenceLine(data: Readonly<Record<string, string | number | boolean>> | undefined): HTMLElement | null {
  if (!data) return null;
  const parts: string[] = [];
  if (typeof data.matched === 'string') parts.push(data.matched);
  if (typeof data.brand === 'string' && data.brand.length > 0) parts.push(data.brand);
  if (typeof data.skeleton === 'string') parts.push(`-> ${data.skeleton}`);
  if (typeof data.shortener === 'string' && data.shortener.length > 0) parts.push(data.shortener);
  if (parts.length === 0) return null;
  return el('span', { class: 'blocked-reason-evidence', text: parts.join('  |  ') });
}

function renderProvenance(details: BlockDetails | null, analysis: AnalysisResult | null): HTMLElement | null {
  const provider = details?.sourceProvider ?? null;
  if (!provider && !analysis?.allowlisted) return null;

  const rows: HTMLElement[] = [];
  if (provider) {
    rows.push(
      el('dt', { text: t('blocked_source') }),
      el('dd', {}, [
        el('span', { text: provider.name }),
        el('span', { class: 'faint small', text: ` - ${provider.license}` }),
      ]),
    );
    rows.push(
      el('dt', { text: t('lists_source') }),
      el('dd', {}, [
        el('a', { href: provider.homepage, target: '_blank', rel: 'noreferrer noopener', text: provider.homepage }),
      ]),
    );
  }
  const observedAt = analysis?.sources[0]?.observedAt ?? null;
  rows.push(el('dt', { text: t('blocked_source_date') }), el('dd', { text: formatDateTime(observedAt) }));

  return el('section', { class: 'blocked-section' }, [
    el('h2', { text: t('lists_status') }),
    el('dl', { class: 'kv' }, rows),
  ]);
}

function renderActions(details: BlockDetails | null): HTMLElement {
  const hostname = details?.hostname ?? null;
  const actions = el('div', { class: 'blocked-actions' }, [
    button({ label: t('blocked_go_back'), variant: 'primary', onClick: () => goBack() }),
    button({
      label: t('blocked_open_dashboard'),
      onClick: async () => {
        await chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
      },
    }),
  ]);

  if (hostname) {
    actions.appendChild(
      button({
        label: t('blocked_allow_site'),
        onClick: async () => {
          await request('allowlist.add', { domain: hostname, scope: 'threats', from: hostname });
          await request('blocked.details', { token: readToken() ?? '' });
          window.location.href = `https://${hostname}/`;
        },
      }),
    );
  }
  return actions;
}

/**
 * "Continue anyway" is intentionally two-step: the user must tick an explicit
 * acknowledgement checkbox before the button becomes usable. There is no silent
 * bypass and no one-click override.
 */
function renderAdvanced(details: BlockDetails | null): HTMLElement | null {
  if (!details?.url) return null;

  let acknowledged = false;
  const confirm = el('input', { type: 'checkbox', id: 'ack-risk' });
  const proceed = button({
    label: t('blocked_advanced_button'),
    variant: 'danger',
    disabled: true,
    onClick: () => {
      if (!acknowledged) return;
      window.location.href = details.url as string;
    },
  });

  confirm.addEventListener('change', () => {
    acknowledged = confirm.checked;
    proceed.disabled = !acknowledged;
  });

  return el('section', { class: 'blocked-advanced' }, [
    el('h2', { text: t('blocked_advanced_title') }),
    el('p', { text: t('blocked_advanced_warning') }),
    toggle({
      id: 'ack-risk',
      label: t('blocked_advanced_toggle'),
      checked: false,
      onChange: (value) => {
        acknowledged = value;
        proceed.disabled = !value;
      },
    }),
    el('div', { class: 'row' }, [proceed]),
    details.matchedDomain !== null && details.hostname !== details.matchedDomain
      ? el('p', {
          class: 'faint small',
          style: 'margin-top:8px',
          text: `${t('blocked_matched_domain')}: ${details.matchedDomain}`,
        })
      : null,
  ]);
}

function goBack(): void {
  if (window.history.length > 1) window.history.back();
  else void chrome.tabs.update({ url: 'chrome://newtab/' });
}

function shieldGlyphLarge(): SVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '26');
  svg.setAttribute('height', '26');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M12 2 4 5v6c0 5 3.4 9.5 8 11 4.6-1.5 8-6 8-11V5l-8-3Z');
  path.setAttribute('fill', 'currentColor');
  const bang = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  bang.setAttribute('d', 'M12 7.5v6M12 16.6v.9');
  bang.setAttribute('stroke', 'currentColor');
  bang.setAttribute('stroke-width', '2');
  bang.setAttribute('stroke-linecap', 'round');
  svg.append(path, bang);
  return svg;
}

void render();
