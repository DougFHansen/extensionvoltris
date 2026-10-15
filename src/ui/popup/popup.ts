/**
 * Popup controller.
 *
 * Every action in the popup is wired to a real service-worker message. There are
 * no decorative buttons (Section 10).
 */
import type { AnalysisResult, Settings, UiLanguage } from '../../core/types';
import { UI_LANGUAGES } from '../../core/types';
import type { StatusResponse } from '../../background/messages';
import { request } from '../../platform/messages';
import {
  applyFavicon,
  applyTheme,
  append,
  badge,
  button,
  clear,
  displayUrl,
  el,
  errorBox,
  formatNumber,
  formatRelative,
  logo,
  spinner,
  t,
  truncateMiddle,
  type BadgeTone,
} from '../shared/components';
import { loadUiLanguage } from '../shared/i18n';

const root = document.getElementById('app');

function verdictTone(verdict: AnalysisResult['verdict'] | undefined): BadgeTone {
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

function categoryKey(category: string): string {
  return `category_${category}`;
}

function reasonText(code: string): string {
  return t(`reason_${code.replace(/\./g, '_')}`);
}

async function patchSettings(patch: Partial<Settings>): Promise<void> {
  const response = await request<Settings>('settings.patch', patch);
  if (!response.ok) return;
  await scheduleRender();
}

/**
 * Serialises rendering.
 *
 * `render()` awaits between clearing the root and writing the new content, so
 * two overlapping renders interleave: one clears while the other is mid-write
 * and both append. The result is duplicated DOM - in practice two `<select>`
 * elements sharing the id `ui-language`, which also breaks every label that
 * points at it.
 *
 * Clicking a dropdown fires a change event per selection, and the settings
 * round-trip is asynchronous, so this race is reachable by an ordinary user
 * clicking quickly. Chaining the renders makes the last one win, cleanly.
 */
let renderQueue: Promise<void> = Promise.resolve();

function scheduleRender(): Promise<void> {
  renderQueue = renderQueue.then(render, render);
  return renderQueue;
}

async function render(): Promise<void> {
  if (!root) return;
  clear(root);
  root.setAttribute('aria-busy', 'true');
  append(root, spinner(t('common_loading')));

  const response = await request<StatusResponse>('get.status');
  root.setAttribute('aria-busy', 'false');
  clear(root);

  if (!response.ok) {
    append(root, el('div', { class: 'popup-body' }, [errorBox(t(response.messageKey))]));
    return;
  }

  const status = response.data;

  // The language override must be applied before anything is rendered, since
  // every label below resolves through it.
  await loadUiLanguage(status.settings.uiLanguage);

  applyTheme(status.settings.theme, status.settings.reducedMotion);
  append(root, renderTopBar(status));
  append(root, renderBody(status));
  append(root, renderFooter(status));
}

/**
 * Language picker in the header.
 *
 * `auto` is the default and means "follow the browser", which is what
 * `chrome.i18n` already does. Choosing a language explicitly persists it, so the
 * choice survives a browser restart and applies to every surface.
 *
 * A `<select>` is used rather than a custom menu: it is keyboard accessible and
 * screen-reader correct with no extra code, and it works identically on every
 * platform.
 */
function renderLanguagePicker(status: StatusResponse): HTMLElement {
  const select = el('select', {
    id: 'ui-language',
    class: 'popup-lang',
    title: t('lang_label'),
    'aria-label': t('lang_label'),
  }) as HTMLSelectElement;

  for (const value of UI_LANGUAGES) {
    // Each option is written in its own language, so someone who cannot read the
    // current interface can still find their language.
    const option = el('option', { value, text: t(`lang_${value}`) });
    option.selected = value === status.settings.uiLanguage;
    select.appendChild(option);
  }

  select.addEventListener('change', () => {
    void patchSettings({ uiLanguage: select.value as UiLanguage });
  });

  return el('div', { class: 'popup-lang-wrap' }, [select]);
}

function renderTopBar(status: StatusResponse): HTMLElement {
  const master = el('input', { type: 'checkbox', id: 'master', class: 'visually-hidden' });
  master.checked = status.settings.protectionEnabled;
  master.addEventListener('change', () => {
    void patchSettings({ protectionEnabled: master.checked });
  });

  return el('header', { class: 'popup-top' }, [
    el('div', { class: 'popup-brand' }, [
      logo(26),
      el('div', { class: 'popup-title' }, [
        el('strong', { text: t('extension_name') }),
        el('span', { text: t('app_tagline') }),
      ]),
    ]),
    el('div', { class: 'popup-header-controls' }, [
      renderLanguagePicker(status),
      el('label', { class: 'popup-master', for: 'master' }, [
        master,
        el('span', {
          text: status.settings.protectionEnabled ? t('common_on') : t('common_off'),
        }),
      ]),
    ]),
  ]);
}

function renderBody(status: StatusResponse): HTMLElement {
  const body = el('div', { class: 'popup-body' });
  body.appendChild(renderSiteCard(status));

  const today = new Date().toISOString().slice(0, 10);
  const blockedToday = status.stats.blockedByDay[today] ?? 0;

  // Every cell below is a real, production-observable number:
  //   - blocked navigations, from `webNavigation.onErrorOccurred`
  //   - the installed rule count, read back from the DNR engine
  // There is deliberately no per-request counter here; see METRIC_CAPABILITIES.
  body.appendChild(
    el('div', { class: 'popup-stats' }, [
      statCell(t('popup_blocked_today'), formatNumber(blockedToday)),
      statCell(t('popup_blocked_total'), formatNumber(status.stats.blockedNavigations)),
      statCell(t('popup_rules_active'), formatNumber(status.protection.dynamicRuleCount)),
    ]),
  );

  const warning = renderProtectionWarning(status);
  if (warning) body.appendChild(warning);
  body.appendChild(renderToggles(status));
  body.appendChild(renderActions(status));
  return body;
}

/**
 * Loud, plain-language warning when protection is installed but INACTIVE.
 *
 * This panel exists because of a shipping fault. The feed pipeline refused the
 * real threat lists, so no rule was ever installed; the extension still rendered
 * a normal-looking popup with protection "On" and a rule count of 0. A user had
 * no way to tell that nothing was being blocked.
 *
 * Silent failure is the worst possible behaviour for a security product, so an
 * installed-but-empty rule set is called out above everything else.
 */
function renderProtectionWarning(status: StatusResponse): HTMLElement | null {
  const { protection, settings } = status;

  // Protection deliberately turned off is a choice, not a fault. Do not scold.
  if (!settings.protectionEnabled) return null;

  if (protection.dynamicRuleCount > 0) return null;

  const failed = protection.rulesMeta?.lastError ?? null;

  return el('section', { class: 'popup-alert', role: 'alert' }, [
    el('strong', { text: t('popup_not_protected_title') }),
    el('p', { text: t('popup_not_protected_body') }),
    failed ? el('p', { class: 'small mono', text: failed }) : null,
    button({
      label: t('popup_not_protected_action'),
      full: true,
      onClick: async () => {
        await request('feeds.refresh', {});
        await scheduleRender();
      },
    }),
  ]);
}

function statCell(label: string, value: string): HTMLElement {
  return el('div', { class: 'popup-stat', title: label }, [el('b', { text: value }), el('span', { text: label })]);
}

function renderSiteCard(status: StatusResponse): HTMLElement {
  const tab = status.currentTab;
  const analysis = tab?.analysis ?? null;

  if (!tab || !tab.url) {
    return el('section', { class: 'site-card' }, [
      el('p', { class: 'muted', text: t('popup_no_site') }),
      el('p', { class: 'small muted', text: t('popup_no_site_hint') }),
    ]);
  }

  const host = analysis?.hostname ?? displayUrl(tab.url);
  const verdict = analysis?.verdict;

  const favicon = el('span', { class: 'site-favicon', 'aria-hidden': 'true' });
  applyFavicon(favicon, tab.url);

  const top = el('div', { class: 'site-card-top' }, [
    el('div', { class: 'site-host' }, [
      favicon,
      el('span', { class: 'site-hostname', title: host, text: truncateMiddle(host, 40) }),
    ]),
    badge(t(verdictKey(verdict)), verdictTone(verdict)),
  ]);

  const children: (HTMLElement | null)[] = [top, el('p', { class: 'site-verdict-hint', text: t(`${verdictKey(verdict)}_hint`) })];

  const reasons = (analysis?.reasons ?? []).filter((r) => r.weight > 0).slice(0, 4);
  if (reasons.length > 0) {
    children.push(
      el(
        'ul',
        { class: 'reason-list' },
        reasons.map((reason) =>
          el('li', { class: 'reason-item' }, [
            el('span', { class: `reason-dot reason-dot-${reason.severity}`, 'aria-hidden': 'true' }),
            el('span', { text: reasonText(reason.code) }),
          ]),
        ),
      ),
    );
  }

  const categories = analysis?.categories ?? [];
  if (categories.length > 0) {
    children.push(
      el('div', { class: 'row' }, categories.slice(0, 3).map((c) => badge(t(categoryKey(c)), verdictTone(verdict)))),
    );
  }

  return el('section', { class: 'site-card' }, children);
}

function miniToggle(
  label: string,
  checked: boolean,
  disabled: boolean,
  onChange: (value: boolean) => Promise<void>,
): HTMLElement {
  const input = el('input', { type: 'checkbox' });
  input.checked = checked;
  input.disabled = disabled;
  const wrapper = el('label', { class: 'mini-toggle', 'data-disabled': String(disabled) }, [
    input,
    el('span', { text: label }),
  ]);
  input.addEventListener('change', () => {
    void onChange(input.checked);
  });
  return wrapper;
}

function renderToggles(status: StatusResponse): HTMLElement {
  const settings = status.settings;
  const master = settings.protectionEnabled;

  return el('div', { class: 'popup-toggles' }, [
    miniToggle(t('popup_toggle_trackers'), settings.blockTrackers, !master, async (v) => {
      await patchSettings({ blockTrackers: v });
    }),
    miniToggle(t('popup_toggle_ads'), settings.blockAds, !master, async (v) => {
      await patchSettings({ blockAds: v });
    }),
    miniToggle(t('popup_toggle_phishing'), settings.blockPhishing, !master, async (v) => {
      await patchSettings({ blockPhishing: v });
    }),
    miniToggle(t('popup_toggle_downloads'), settings.downloadProtection, !master, async (v) => {
      await patchSettings({ downloadProtection: v });
    }),
  ]);
}

function renderActions(status: StatusResponse): HTMLElement {
  const domain = status.currentTab?.analysis?.registrableDomain ?? null;

  const actions = el('div', { class: 'popup-actions' }, [
    button({
      label: t('popup_open_dashboard'),
      variant: 'primary',
      full: true,
      onClick: async () => {
        await chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
      },
    }),
    button({
      label: t('popup_open_settings'),
      full: true,
      onClick: () => chrome.runtime.openOptionsPage(),
    }),
  ]);

  if (domain) {
    actions.appendChild(
      button({
        label: t('popup_allow_site'),
        full: true,
        onClick: async () => {
          await request('allowlist.add', { domain, scope: 'threats', from: domain });
          await scheduleRender();
        },
      }),
    );
    actions.appendChild(
      button({
        label: t('popup_rescan_page'),
        full: true,
        onClick: async () => {
          if (status.currentTab) await request('page.rescan', { tabId: status.currentTab.id });
          await scheduleRender();
        },
      }),
    );
  }

  return actions;
}

function renderFooter(status: StatusResponse): HTMLElement {
  const updatedAt = status.protection.datasetUpdatedAt;
  return el('footer', { class: 'popup-footer' }, [
    el('span', { text: `${t('popup_last_update')}: ${formatRelative(updatedAt)}` }),
    status.protection.rulesMeta
      ? el('span', {
          class: 'mono',
          text: `${formatNumber(status.protection.dynamicRuleCount)} DNR`,
        })
      : null,
  ]);
}

void scheduleRender();

// Keep the popup responsive to settings changes made in another surface.
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && 'vbs.settings' in changes) void scheduleRender();
});
