/**
 * Dashboard.
 *
 * Reads everything through a single `get.dashboard` message so the whole page
 * renders from one consistent snapshot instead of racing several requests.
 */
import type { HistoryEvent } from '../../core/types';
import { METRIC_CAPABILITIES } from '../../core/types';
import type { DashboardResponse } from '../../background/messages';
import { request } from '../../platform/messages';
import { loadUiLanguage } from '../shared/i18n';
import { getSettings, updateSettings } from '../../data/settings';
import {
  append,
  applyTheme,
  badge,
  barChart,
  button,
  card,
  clear,
  el,
  emptyState,
  errorBox,
  formatDateTime,
  formatNumber,
  formatRelative,
  logo,
  spinner,
  statTile,
  t,
  type Child,
} from '../shared/components';

type TabId = 'overview' | 'events' | 'sites' | 'lists' | 'resources' | 'permissions' | 'privacy';

const navSlot = document.getElementById('dash-nav');
const panelSlot = document.getElementById('dash-panels');
let activeTab: TabId = 'overview';
let snapshot: DashboardResponse | null = null;
let eventFilter: HistoryEvent['kind'] | 'all' = 'all';

const TABS: { id: TabId; key: string }[] = [
  { id: 'overview', key: 'dash_tab_overview' },
  { id: 'events', key: 'dash_tab_events' },
  { id: 'sites', key: 'dash_tab_sites' },
  { id: 'lists', key: 'dash_tab_lists' },
  { id: 'resources', key: 'dash_tab_resources' },
  { id: 'permissions', key: 'dash_tab_permissions' },
  { id: 'privacy', key: 'dash_tab_privacy' },
];

function requireSnapshot(): DashboardResponse {
  if (!snapshot) throw new Error('snapshot unavailable');
  return snapshot;
}

function severityTone(kind: HistoryEvent['kind']): 'danger' | 'warn' | 'ok' | 'info' | 'neutral' {
  switch (kind) {
    case 'threat_blocked':
    case 'list_error':
      return 'danger';
    case 'suspicious_detected':
    case 'scam_signals':
    case 'download_flagged':
      return 'warn';
    case 'list_updated':
    case 'allowlist_changed':
      return 'ok';
    case 'tracker_blocked':
    case 'ad_blocked':
      return 'info';
    default:
      return 'neutral';
  }
}

function eventLabel(kind: HistoryEvent['kind']): string {
  return t(`event_${kind}`);
}

async function refresh(): Promise<void> {
  const settings = await getSettings();
  // The override must be in place before any label is rendered.
  await loadUiLanguage(settings.uiLanguage);
  applyTheme(settings.theme, settings.reducedMotion);

  const response = await request<DashboardResponse>('get.dashboard', {});
  snapshot = response.ok ? response.data : null;
  await renderPanel();
}

function renderNav(): void {
  if (!navSlot) return;
  clear(navSlot);
  for (const tab of TABS) {
    const btn = el('button', {
      type: 'button',
      role: 'tab',
      id: `dash-tab-${tab.id}`,
      text: t(tab.key),
      'aria-selected': String(tab.id === activeTab),
    });
    btn.addEventListener('click', () => {
      activeTab = tab.id;
      void renderPanel();
    });
    navSlot.appendChild(btn);
  }
}

async function renderPanel(): Promise<void> {
  if (!panelSlot || !navSlot) return;
  for (const child of Array.from(navSlot.children)) {
    child.setAttribute('aria-selected', String(child.id === `dash-tab-${activeTab}`));
  }
  clear(panelSlot);
  append(panelSlot, spinner(t('common_loading')));

  if (!snapshot) {
    clear(panelSlot);
    append(panelSlot, errorBox(t('error_service_worker')));
    return;
  }

  const renderers: Record<TabId, () => Child[]> = {
    overview: renderOverview,
    events: renderEvents,
    sites: renderSites,
    lists: renderLists,
    resources: renderResources,
    permissions: renderPermissions,
    privacy: renderPrivacy,
  };

  const content = renderers[activeTab]();
  clear(panelSlot);
  append(panelSlot, el('div', { class: 'page-panel', role: 'tabpanel' }, content));
}

// --------------------------------------------------------------- overview

function renderOverview(): Child[] {
  const data = requireSnapshot();
  const { stats, protection } = data.status;
  const today = new Date().toISOString().slice(0, 10);
  const todayCount = stats.blockedByDay[today] ?? 0;
  const byCategory = stats.blockedNavigationsByCategory;

  const topDomains = Object.entries(stats.topBlockedDomains).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return [
    card({ title: t('dash_summary') }, [
      el('div', { class: 'stat-grid' }, [
        statTile({ label: t('popup_blocked_today'), value: formatNumber(todayCount), tone: todayCount > 0 ? 'ok' : 'neutral' }),
        statTile({ label: t('popup_blocked_total'), value: formatNumber(stats.blockedNavigations), tone: stats.blockedNavigations > 0 ? 'ok' : 'neutral' }),
        statTile({ label: t('popup_rules_active'), value: formatNumber(protection.dynamicRuleCount) }),
        statTile({ label: t('event_download_flagged'), value: formatNumber(stats.downloadsFlagged) }),
        statTile({ label: t('event_suspicious_detected'), value: formatNumber(stats.suspiciousDetected), tone: stats.suspiciousDetected > 0 ? 'warn' : 'neutral' }),
        statTile({ label: t('resource_allowlist'), value: formatNumber(stats.allowlisted) }),
      ]),
      el('p', { class: 'hint small muted', text: t('dash_summary_scope') }),
    ]),
    card({ title: t('dash_what_we_measure') }, [
      el('ul', { class: 'metric-list' }, [
        metricRow('blockedNavigations', 'metric_observed_blocks', 'metric_observed_blocks_hint'),
        metricRow('detections', 'metric_detections', 'metric_detections_hint'),
        metricRow('downloadWarnings', 'metric_download_warnings', 'metric_download_warnings_hint'),
        metricRow('rulesInstalled', 'metric_rules_installed', 'metric_rules_installed_hint'),
        metricRow('subResourceRequestsBlocked', 'metric_subresource_blocks', 'metric_subresource_blocks_hint'),
      ]),
    ]),
    card({ title: t('dash_last_14_days') }, [barChart(data.daily)]),
    card(
      { title: t('dash_statistics_by_category') },
      el('div', { class: 'stat-grid' }, [
        statTile({ label: t('category_phishing'), value: formatNumber(byCategory.phishing ?? 0) }),
        statTile({ label: t('category_malware'), value: formatNumber((byCategory.malware ?? 0) + (byCategory.malware_distribution ?? 0)) }),
        statTile({ label: t('category_scam'), value: formatNumber(byCategory.scam ?? 0) }),
      ]),
    ),
    card(
      { title: t('dash_top_blocked') },
      topDomains.length === 0
        ? emptyState(t('dash_no_events'), t('dash_no_events_hint'))
        : el(
            'div',
            { class: 'data-table-wrap' },
            [
              el('table', { class: 'data-table' }, [
                el('thead', {}, [el('tr', {}, [el('th', { text: t('blocked_domain') }), el('th', { text: t('popup_blocked_total') })])]),
                el(
                  'tbody',
                  {},
                  topDomains.map(([domain, count]) =>
                    el('tr', {}, [el('td', { class: 'mono', text: domain }), el('td', { class: 'mono', text: formatNumber(count) })]),
                  ),
                ),
              ]),
            ],
          ),
    ),
  ];
}

/**
 * One row of the "what we measure" disclosure.
 *
 * `available` is read from `METRIC_CAPABILITIES`, the same constant the
 * service worker publishes, so this panel can never drift from the real
 * capability set. An unmeasurable metric is rendered explicitly rather than
 * hidden: omitting it would leave the user unable to tell "quiet day" apart
 * from "broken counter".
 */
function metricRow(capabilityId: keyof typeof METRIC_CAPABILITIES, labelKey: string, hintKey: string): HTMLElement {
  const available: boolean = METRIC_CAPABILITIES[capabilityId];
  return el('li', { class: available ? 'metric-row' : 'metric-row is-unavailable' }, [
    el('span', { class: 'metric-badge', 'aria-hidden': 'true', text: available ? '\u2713' : '\u2014' }),
    el('div', { class: 'metric-text' }, [
      el('strong', { text: t(labelKey) }),
      el('span', { class: 'small muted', text: t(hintKey) }),
    ]),
    el('span', { class: 'metric-state small', text: available ? t('metric_available') : t('metric_not_available') }),
  ]);
}

// ----------------------------------------------------------------- events

function renderEvents(): Child[] {
  const data = requireSnapshot();
  const all = data.history;
  const visible = eventFilter === 'all' ? all : all.filter((e) => e.kind === eventFilter);

  const kinds = [...new Set(all.map((e) => e.kind))];

  const filterBar = el('div', { class: 'row' }, [
    button({
      label: t('dash_show_all'),
      variant: eventFilter === 'all' ? 'primary' : 'secondary',
      onClick: async () => {
        eventFilter = 'all';
        await renderPanel();
      },
    }),
    ...kinds.map((kind) =>
      button({
        label: eventLabel(kind),
        variant: eventFilter === kind ? 'primary' : 'secondary',
        onClick: async () => {
          eventFilter = kind;
          await renderPanel();
        },
      }),
    ),
  ]);

  return [
    card(
      {
        title: t('dash_tab_events'),
        subtitle: `${visible.length} / ${all.length}`,
        actions: button({
          label: t('dash_clear_history'),
          variant: 'danger',
          onClick: async () => {
            await request('history.clear', {});
            await refresh();
          },
        }),
      },
      all.length === 0
        ? emptyState(t('dash_no_events'), t('dash_no_events_hint'))
        : el('div', {}, [filterBar, el('hr', { class: 'divider' }), renderEventList(visible)]),
    ),
  ];
}

function renderEventList(events: readonly HistoryEvent[]): HTMLElement {
  return el(
    'div',
    {},
    events.slice(0, 100).map((event) =>
      el('div', { class: 'event-row' }, [
        el('span', { class: `event-marker ${severityTone(event.kind)}`, 'aria-hidden': 'true' }),
        el('div', { class: 'event-main' }, [
          el('div', { class: 'event-title' }, [
            el('span', { text: eventLabel(event.kind) }),
            event.category ? badge(t(`category_${event.category}`), 'neutral') : null,
          ]),
          el('div', {
            class: 'event-sub',
            title: event.url ?? event.domain,
            text: event.url ?? event.domain ?? '',
          }),
        ]),
        el('div', { class: 'event-time' }, [
          el('div', { text: formatRelative(event.at) }),
          button({
            label: t('common_delete'),
            variant: 'ghost',
            onClick: async () => {
              await request('history.delete', { id: event.id });
              await refresh();
            },
          }),
        ]),
      ]),
    ),
  );
}

// ------------------------------------------------------------------ sites

function renderSites(): Child[] {
  const data = requireSnapshot();
  return [
    card(
      { title: t('dash_tab_sites'), subtitle: `${data.allowlist.length}` },
      data.allowlist.length === 0
        ? emptyState(t('dash_no_sites'), t('dash_no_sites_hint'), button({ label: t('popup_open_settings'), onClick: () => chrome.runtime.openOptionsPage() }))
        : el(
            'div',
            {},
            data.allowlist.map((entry) =>
              el('div', { class: 'site-row' }, [
                el('div', { class: 'site-row-main' }, [
                  el('div', { class: 'site-row-domain', text: entry.domain }),
                  el('div', { class: 'site-row-meta', text: `${t(`sites_scope_${entry.scope}`)} - ${formatRelative(entry.addedAt)}` }),
                ]),
                el('div', { class: 'site-row-actions' }, [
                  button({
                    label: t('common_remove'),
                    variant: 'danger',
                    onClick: async () => {
                      await request('allowlist.remove', { domain: entry.domain });
                      await refresh();
                    },
                  }),
                ]),
              ]),
            ),
          ),
    ),
  ];
}

// ------------------------------------------------------------------ lists

function renderLists(): Child[] {
  const data = requireSnapshot();
  return [
    card(
      {
        title: t('dash_tab_lists'),
        subtitle: `${t('lists_revision')}: ${data.feeds.revision} - ${t('lists_updated_at')}: ${formatDateTime(data.feeds.updatedAt)}`,
        actions: button({
          label: t('lists_update_now'),
          variant: 'primary',
          onClick: async (event) => {
            const target = event.currentTarget as HTMLButtonElement;
            target.disabled = true;
            target.textContent = t('lists_updating');
            await request('feeds.refresh', {});
            await refresh();
          },
        }),
      },
      data.feeds.states.length === 0
        ? emptyState(t('lists_no_provider'))
        : el('div', { class: 'data-table-wrap' }, [
            el('table', { class: 'data-table' }, [
              el('thead', {}, [
                el('tr', {}, [
                  el('th', { text: t('lists_status') }),
                  el('th', { text: t('lists_source') }),
                  el('th', { text: t('lists_license') }),
                  el('th', { text: t('lists_entries') }),
                  el('th', { text: t('lists_updated_at') }),
                ]),
              ]),
              el(
                'tbody',
                {},
                data.feeds.states.map((state) =>
                  el('tr', {}, [
                    el('td', {}, [badge(t(`provider_status_${state.status}`), stateTone(state.status))]),
                    el('td', {}, [
                      el('div', { text: state.id }),
                      state.lastError ? el('div', { class: 'small', style: 'color:var(--vbs-danger)', text: state.lastError }) : null,
                    ]),
                    el('td', { class: 'small', text: data.feeds.configured.includes(state.id) ? t('opt_credential_configured') : t('opt_credential_missing') }),
                    el('td', { class: 'mono', text: formatNumber(state.entryCount) }),
                    el('td', { class: 'small', text: formatRelative(state.lastSuccessAt) }),
                  ]),
                ),
              ),
            ]),
          ]),
    ),
  ];
}

function stateTone(status: string): 'ok' | 'warn' | 'danger' | 'neutral' {
  switch (status) {
    case 'active':
      return 'ok';
    case 'stale':
    case 'not_configured':
      return 'warn';
    case 'error':
      return 'danger';
    default:
      return 'neutral';
  }
}

// -------------------------------------------------------------- resources

function renderResources(): Child[] {
  const data = requireSnapshot();
  const p = data.status.protection;
  const budget = p.rulesMeta ? 30_000 : 0;

  return [
    card({ title: t('dash_resources_active') }, [
      el('dl', { class: 'kv' }, [
        el('dt', { text: t('resource_dnr') }),
        el('dd', { text: t('resource_dnr_hint', `${formatNumber(p.dynamicRuleCount)} / ${formatNumber(budget)}`) }),
        el('dt', { text: t('resource_allowlist') }),
        el('dd', { text: t('resource_allowlist_hint', formatNumber(p.sessionRuleCount)) }),
        el('dt', { text: t('resource_psl') }),
        el('dd', { text: t('resource_psl_hint', `${formatNumber(p.psl.ruleCount)} (${p.psl.origin})`) }),
        el('dt', { text: t('opt_hover_warnings') }),
        el('dd', { text: t('resource_hover_hint') }),
        el('dt', { text: t('opt_scam_page') }),
        el('dd', { text: t('resource_scams_hint') }),
        el('dt', { text: t('opt_download_protection') }),
        el('dd', { text: t('resource_downloads_hint', data.status.settings.downloadAction) }),
      ]),
    ]),
    card({ title: t('tab_web_protection') }, [
      el('dl', { class: 'kv' }, [
        el('dt', { text: t('opt_protection_enabled') }),
        el('dd', {}, [badge(data.status.settings.protectionEnabled ? t('common_on') : t('common_off'), data.status.settings.protectionEnabled ? 'ok' : 'neutral')]),
        el('dt', { text: t('popup_protections') }),
        el('dd', { text: enabledCategories(data.status.settings).join(', ') || t('common_none') }),
      ]),
    ]),
  ];
}

function enabledCategories(settings: ReturnType<typeof requireSnapshot>['status']['settings']): string[] {
  const out: string[] = [];
  if (settings.blockMalware) out.push(t('category_malware'));
  if (settings.blockPhishing) out.push(t('category_phishing'));
  if (settings.blockScam) out.push(t('category_scam'));
  if (settings.blockTrackers) out.push(t('category_tracker'));
  if (settings.blockAds) out.push(t('category_ad'));
  return out;
}

// ------------------------------------------------------------ permissions

function renderPermissions(): Child[] {
  requireSnapshot();
  const manifest = chrome.runtime.getManifest();
  const granted = new Set<string>(manifest.permissions ?? []);

  // Justification for every permission the shipped manifest actually declares.
  //
  // Keyed by name and derived from the manifest itself, so this table can never
  // advertise a permission we do not request. It previously listed
  // `declarativeNetRequestFeedback`, which rendered as "missing" and implied we
  // were asking for it.
  const JUSTIFICATION: Record<string, string> = {
    storage: 'permission_storage',
    alarms: 'permission_alarms',
    declarativeNetRequest: 'permission_dnr',
    webNavigation: 'permission_webnavigation',
    downloads: 'permission_downloads',
    notifications: 'permission_notifications',
    scripting: 'permission_scripting',
  };

  const rows = [...granted].map((name) =>
    el('tr', {}, [
      el('td', { class: 'mono', text: name }),
      el('td', {}, [badge(t('perm_present'), 'ok')]),
      el('td', { class: 'small', text: t(JUSTIFICATION[name] ?? 'perm_no_justification') }),
    ]),
  );

  rows.push(
    el('tr', {}, [
      el('td', { class: 'mono', text: '<all_urls>' }),
      el('td', {}, [badge(t('perm_present'), 'warn')]),
      el('td', { class: 'small', text: t('perm_host_access_hint') }),
    ]),
  );

  const header = el('tr', {}, [
    el('th', { text: t('lists_format') }),
    el('th', { text: t('lists_status') }),
    el('th', { text: t('blocked_reason') }),
  ]);

  const table = el('table', { class: 'data-table' }, [
    el('thead', {}, [header]),
    el('tbody', {}, rows),
  ]);

  return [
    card({ title: t('perm_title'), subtitle: t('perm_intro') }, el('div', { class: 'data-table-wrap' }, [table])),
  ];
}

// ---------------------------------------------------------------- privacy

function renderPrivacy(): Child[] {
  const data = requireSnapshot();
  return [
    card({ title: t('dash_tab_privacy'), subtitle: t('privacy_intro') }, [
      el('div', { class: 'privacy-grid' }, [
        el('div', {}, [
          el('h3', { class: 'settings-group-title', text: t('privacy_never_title') }),
          el(
            'ul',
            { class: 'privacy-list' },
            [t('privacy_never'), t('privacy_never_2'), t('privacy_never_3'), t('privacy_never_4'), t('privacy_never_5')].map((label) =>
              el('li', {}, [el('span', { class: 'privacy-icon no', 'aria-hidden': 'true', text: '!' }), el('span', { text: label })]),
            ),
          ),
        ]),
        el('div', {}, [
          el('h3', { class: 'settings-group-title', text: t('privacy_stored_title') }),
          el(
            'ul',
            { class: 'privacy-list' },
            [t('privacy_stored_2'), t('privacy_stored_3'), t('privacy_stored_4'), t('privacy_stored_5')].map((label) =>
              el('li', {}, [el('span', { class: 'privacy-icon yes', 'aria-hidden': 'true', text: '+' }), el('span', { text: label })]),
            ),
          ),
        ]),
      ]),
    ]),
    card(
      { title: t('privacy_limits_title'), subtitle: t('privacy_limits_intro') },
      el('p', { class: 'small muted', text: t('privacy_limits_body') }),
    ),
    card(
      { title: t('privacy_clear_title'), subtitle: t('privacy_clear_intro') },
      el('div', { class: 'row' }, [
        button({
          label: t('dash_clear_history'),
          onClick: async () => {
            await request('history.clear', {});
            await refresh();
          },
        }),
        button({
          label: t('privacy_clear_all'),
          variant: 'danger',
          onClick: async () => {
            await request('data.clear', {
              settings: true,
              statistics: true,
              allowlist: true,
              history: true,
              threatData: false,
            });
            await refresh();
          },
        }),
      ]),
    ),
    card({ title: t('privacy_storage_usage') }, [
      el('p', { class: 'small muted', text: `${t('lists_revision')}: ${data.feeds.revision}` }),
    ]),
  ];
}

// -------------------------------------------------------------------- init

async function init(): Promise<void> {
  const settings = await getSettings();

  // MUST come before the first `t()` call below. The heading, subtitle and the
  // whole tab bar are written here, ahead of `refresh()`, so loading the
  // override later would leave them in the browser's language while the panel
  // content underneath used the chosen one.
  await loadUiLanguage(settings.uiLanguage);
  applyTheme(settings.theme, settings.reducedMotion);

  const heading = document.getElementById('dash-heading');
  const subtitle = document.getElementById('dash-subtitle');
  const footer = document.getElementById('dash-footer');
  const logoSlot = document.getElementById('logo-slot');
  const themeSlot = document.getElementById('theme-slot');
  const optionsBtn = document.getElementById('open-options');
  const refreshBtn = document.getElementById('refresh');

  if (heading) heading.textContent = t('dash_title');
  if (subtitle) subtitle.textContent = t('dash_subtitle');
  if (footer) footer.textContent = t('about_attribution');
  if (logoSlot) append(logoSlot, logo(30));
  if (themeSlot) {
    append(
      themeSlot,
      el('div', { class: 'segmented', role: 'group' }, (
        [
          { value: 'system', label: t('theme_system') },
          { value: 'light', label: t('theme_light') },
          { value: 'dark', label: t('theme_dark') },
        ] as const
      ).map((option) => {
        const btn = el('button', {
          type: 'button',
          text: option.label,
          'aria-pressed': String(settings.theme === option.value),
        });
        btn.addEventListener('click', async () => {
          await updateSettings({ theme: option.value });
          applyTheme(option.value, settings.reducedMotion);
          await refresh();
        });
        return btn;
      })),
    );
  }

  optionsBtn?.addEventListener('click', () => chrome.runtime.openOptionsPage());
  refreshBtn?.addEventListener('click', () => void refresh());

  renderNav();
  await refresh();

  // Live counter refresh without polling: storage changes drive the update.
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && ('vbs.stats' in changes || 'vbs.history' in changes)) void refresh();
  });
}

void init();
