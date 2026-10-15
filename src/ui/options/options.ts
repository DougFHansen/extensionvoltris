/**
 * Settings surface.
 *
 * All eight tabs required by the specification are implemented, and every
 * control in them is wired to a real service-worker call. There are no
 * decorative controls.
 */
import type { Settings } from '../../core/types';
import type { DiagnosticsResponse } from '../../background/messages';
import { FEED_REGISTRY } from '../../feeds/registry';
import { request } from '../../platform/messages';
import { loadUiLanguage } from '../shared/i18n';
import {
  append,
  applyTheme,
  badge,
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
  toggle,
  type BadgeTone,
  type Child,
} from '../shared/components';
import { getSettings, updateSettings } from '../../data/settings';

interface AllowlistViewEntry {
  readonly domain: string;
  readonly scope: 'all' | 'threats' | 'privacy';
  readonly addedAt: number;
  readonly enabled: boolean;
}

type TabId =
  | 'web'
  | 'phishing'
  | 'privacy'
  | 'downloads'
  | 'sites'
  | 'updates'
  | 'diagnostics'
  | 'about';

interface Tab {
  readonly id: TabId;
  readonly labelKey: string;
  readonly render: () => Promise<Child[]>;
}

const navSlot = document.getElementById('settings-nav');
const panelSlot = document.getElementById('settings-panels');
let activeTab: TabId = 'web';

async function patch(change: Partial<Settings>): Promise<void> {
  await updateSettings(change);
  const settings = await getSettings();
  // A language change must take effect on this page immediately, not on reload.
  await loadUiLanguage(settings.uiLanguage);
  applyTheme(settings.theme, settings.reducedMotion);
  await renderActiveTab();
}

// ---------------------------------------------------------------- tab: web

async function renderWeb(): Promise<Child[]> {
  const settings = await getSettings();
  return [
    card(
      { title: t('tab_web_protection') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'protectionEnabled',
          label: t('opt_protection_enabled'),
          hint: t('opt_protection_enabled_hint'),
          checked: settings.protectionEnabled,
          onChange: (v) => patch({ protectionEnabled: v }),
        }),
      ]),
    ),
    card(
      { title: t('popup_protections') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'blockMalware',
          label: t('opt_block_malware'),
          checked: settings.blockMalware,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockMalware: v }),
        }),
        toggle({
          id: 'blockPhishing',
          label: t('opt_block_phishing'),
          checked: settings.blockPhishing,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockPhishing: v }),
        }),
        toggle({
          id: 'blockScam',
          label: t('opt_block_scam'),
          checked: settings.blockScam,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockScam: v }),
        }),
        toggle({
          id: 'blockMalwareDistribution',
          label: t('opt_block_malware_distribution'),
          checked: settings.blockMalwareDistribution,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockMalwareDistribution: v }),
        }),
      ]),
    ),
  ];
}

// ----------------------------------------------------------- tab: phishing

async function renderPhishing(): Promise<Child[]> {
  const settings = await getSettings();
  return [
    card(
      { title: t('tab_phishing'), subtitle: t('verdict_no_threat_found_hint') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'phishingEngineEnabled',
          label: t('opt_phishing_engine'),
          hint: t('opt_phishing_engine_hint'),
          checked: settings.phishingEngineEnabled,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ phishingEngineEnabled: v }),
        }),
        toggle({
          id: 'showHoverWarnings',
          label: t('opt_hover_warnings'),
          hint: t('opt_hover_warnings_hint'),
          checked: settings.showHoverWarnings,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ showHoverWarnings: v }),
        }),
        toggle({
          id: 'scamPageAnalysis',
          label: t('opt_scam_page'),
          hint: t('opt_scam_page_hint'),
          checked: settings.scamPageAnalysis,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ scamPageAnalysis: v }),
        }),
      ]),
    ),
  ];
}

// ------------------------------------------------------------ tab: privacy

async function renderPrivacyTab(): Promise<Child[]> {
  const settings = await getSettings();
  return [
    card(
      { title: t('tab_privacy') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'blockTrackers',
          label: t('opt_block_trackers'),
          checked: settings.blockTrackers,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockTrackers: v }),
        }),
        toggle({
          id: 'blockAds',
          label: t('opt_block_ads'),
          checked: settings.blockAds,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockAds: v }),
        }),
        toggle({
          id: 'blockThirdPartyOnly',
          label: t('opt_block_third_party_only'),
          hint: t('opt_block_third_party_only_hint'),
          checked: settings.blockThirdPartyOnly,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ blockThirdPartyOnly: v }),
        }),
      ]),
    ),
    card(
      { title: t('dash_tab_privacy') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'storeHistory',
          label: t('opt_store_history'),
          hint: t('opt_store_history_hint'),
          checked: settings.storeHistory,
          onChange: (v) => patch({ storeHistory: v }),
        }),
        toggle({
          id: 'storeFullUrls',
          label: t('opt_store_full_urls'),
          hint: t('opt_store_full_urls_hint'),
          checked: settings.storeFullUrls,
          disabled: !settings.storeHistory,
          onChange: (v) => patch({ storeFullUrls: v }),
        }),
        toggle({
          id: 'showNotifications',
          label: t('opt_notifications'),
          checked: settings.showNotifications,
          onChange: (v) => patch({ showNotifications: v }),
        }),
      ]),
    ),
    card(
      { title: t('opt_theme') },
      el('div', { class: 'row' }, [
        segmented(
          [
            { value: 'system', label: t('theme_system') },
            { value: 'light', label: t('theme_light') },
            { value: 'dark', label: t('theme_dark') },
          ],
          settings.theme,
          (value) => patch({ theme: value as Settings['theme'] }),
        ),
        toggle({
          id: 'reducedMotion',
          label: t('opt_reduced_motion'),
          checked: settings.reducedMotion,
          onChange: (v) => patch({ reducedMotion: v }),
        }),
      ]),
    ),
  ];
}

// ----------------------------------------------------------- tab: downloads

async function renderDownloadsTab(): Promise<Child[]> {
  const settings = await getSettings();
  const response = await request<{ executable: readonly string[]; archives: readonly string[] }>('download.lists');

  return [
    card(
      { title: t('tab_downloads') },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'downloadProtection',
          label: t('opt_download_protection'),
          checked: settings.downloadProtection,
          disabled: !settings.protectionEnabled,
          onChange: (v) => patch({ downloadProtection: v }),
        }),
        toggle({
          id: 'warnDoubleExtensions',
          label: t('opt_warn_double_ext'),
          checked: settings.warnDoubleExtensions,
          disabled: !settings.downloadProtection,
          onChange: (v) => patch({ warnDoubleExtensions: v }),
        }),
        toggle({
          id: 'warnDangerousExtensions',
          label: t('opt_warn_dangerous_ext'),
          hint: t('opt_warn_dangerous_ext_hint'),
          checked: settings.warnDangerousExtensions,
          disabled: !settings.downloadProtection,
          onChange: (v) => patch({ warnDangerousExtensions: v }),
        }),
        el('div', { class: 'field' }, [
          el('span', { class: 'hint', text: t('opt_download_action_hint') }),
          segmented(
            [
              { value: 'alert', label: t('opt_download_action_alert') },
              { value: 'cancel', label: t('opt_download_action_cancel') },
            ],
            settings.downloadAction,
            (value) => patch({ downloadAction: value as Settings['downloadAction'] }),
          ),
        ]),
      ]),
    ),
    card(
      { title: t('opt_download_protection') },
      el('p', { class: 'callout', text: t('blocked_reports_no_content_scan') }),
    ),
    response.ok
      ? card(
          { title: t('tab_downloads'), subtitle: t('lists_format') },
          el('div', { class: 'stack' }, [
            el('p', { class: 'small muted' }, [
              el('strong', { text: `${t('reason_downloads_dangerous_extension')}: ` }),
              el('span', { class: 'mono', text: response.data.executable.join(' ') }),
            ]),
            el('p', { class: 'small muted' }, [
              el('strong', { text: `${t('tab_downloads')}: ` }),
              el('span', { class: 'mono', text: response.data.archives.join(' ') }),
            ]),
          ]),
        )
      : null,
  ];
}

// --------------------------------------------------------------- tab: sites

async function renderSites(): Promise<Child[]> {
  const response = await request<AllowlistViewEntry[]>('allowlist.list');
  const entries = response.ok ? response.data : [];

  const input = el('input', {
    type: 'text',
    class: 'text-input',
    placeholder: t('sites_domain_placeholder'),
    id: 'allow-domain',
    maxlength: 253,
  });

  let scope: 'all' | 'threats' | 'privacy' = 'privacy';
  const scopeControl = segmented(
    [
      { value: 'privacy', label: t('sites_scope_privacy') },
      { value: 'threats', label: t('sites_scope_threats') },
      { value: 'all', label: t('sites_scope_all') },
    ],
    scope,
    (value) => {
      scope = value as typeof scope;
    },
  );

  const addButton = button({
    label: t('common_add'),
    variant: 'primary',
    onClick: async () => {
      const domain = input.value.trim();
      if (domain.length === 0) return;
      const result = await request('allowlist.add', { domain, scope });
      input.value = '';
      if (!result.ok) {
        addButton.textContent = t('sites_invalid_domain');
        return;
      }
      await renderActiveTab();
    },
  });

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') addButton.click();
  });

  return [
    card(
      { title: t('sites_add_title') },
      el('div', { class: 'stack' }, [
        el('div', { class: 'row' }, [input, addButton]),
        scopeControl,
        el('p', { class: 'hint small muted', id: 'scope-hint' }),
      ]),
    ),
    card(
      { title: t('tab_sites') },
      entries.length === 0
        ? emptyState(t('dash_no_sites'), t('dash_no_sites_hint'))
        : el(
            'div',
            {},
            entries.map((entry) =>
              el('div', { class: 'site-row' }, [
                el('div', { class: 'site-row-main' }, [
                  el('div', { class: 'site-row-domain', text: entry.domain }),
                  el('div', { class: 'site-row-meta', text: `${t(`sites_scope_${entry.scope}`)} - ${formatRelative(entry.addedAt)}` }),
                ]),
                el('div', { class: 'site-row-actions' }, [
                  badge(entry.enabled ? t('common_enabled') : t('common_disabled'), entry.enabled ? 'ok' : 'neutral'),
                  button({
                    label: entry.enabled ? t('common_off') : t('common_on'),
                    variant: 'ghost',
                    onClick: async () => {
                      await request('allowlist.toggle', { domain: entry.domain, enabled: !entry.enabled });
                      await renderActiveTab();
                    },
                  }),
                  button({
                    label: t('common_remove'),
                    variant: 'danger',
                    onClick: async () => {
                      await request('allowlist.remove', { domain: entry.domain });
                      await renderActiveTab();
                    },
                  }),
                ]),
              ]),
            ),
          ),
    ),
  ];
}

// ------------------------------------------------------------- tab: updates

async function renderUpdates(): Promise<Child[]> {
  const settings = await getSettings();
  const response = await request<{
    states: { id: string; status: string; entryCount: number; lastSuccessAt: number | null; lastError: string | null; contentHash: string | null; feedVersion: string | null }[];
    revision: number;
    updatedAt: number;
    configured: string[];
  }>('feeds.state');

  const states = response.ok ? response.data.states : [];
  const configured = new Set(response.ok ? response.data.configured : []);
  const cycleError = response.ok ? (response.data as { cycleError?: { message: string } | null }).cycleError : null;

  /*
   * "NO THREAT DATA" IS THE MOST IMPORTANT THING ON THIS TAB.
   *
   * The updater refused the real feeds for as long as this shipped, so the
   * provider table was legitimately empty and the tab rendered "no provider",
   * which reads like nothing to worry about. Nothing anywhere said the extension
   * was blocking nothing.
   *
   * An empty list is therefore treated as a fault, not an empty state: the panel
   * below leads with the fact that protection is not active.
   */
  const noThreatData = states.filter((s) => s.status === 'active' || s.status === 'stale').length === 0;

  return [
    ...(noThreatData
      ? [
          card({ title: t('lists_no_data_title') }, [
            el('p', { text: t('lists_no_data_body') }),
            cycleError ? el('p', { class: 'small mono', text: cycleError.message }) : null,
            button({
              label: t('lists_update_now'),
              variant: 'primary',
              onClick: async () => {
                await request('feeds.refresh', {});
                await renderActiveTab();
              },
            }),
          ]),
        ]
      : []),
    card(
      {
        title: t('lists_title'),
        subtitle: t('lists_data_only'),
        actions: button({
          label: t('lists_update_now'),
          variant: 'primary',
          onClick: async (event) => {
            const target = event.currentTarget as HTMLButtonElement;
            target.disabled = true;
            target.textContent = t('lists_updating');
            await request('feeds.refresh', {});
            target.disabled = false;
            target.textContent = t('lists_update_now');
            await renderActiveTab();
          },
        }),
      },
      el('div', { class: 'settings-group' }, [
        toggle({
          id: 'autoUpdate',
          label: t('lists_auto_update'),
          checked: settings.autoUpdate,
          onChange: (v) => patch({ autoUpdate: v }),
        }),
        el('div', { class: 'field' }, [
          el('label', { for: 'interval', text: t('opt_update_interval') }),
          segmented(
            [6, 12, 24, 72].map((h) => ({ value: String(h), label: t('lists_interval_hours', String(h)) })),
            String(settings.updateIntervalHours),
            (value) => patch({ updateIntervalHours: Number(value) }),
          ),
        ]),
      ]),
    ),
    card(
      {
        title: t('lists_title'),
        subtitle: response.ok ? `${t('lists_revision')}: ${response.data.revision} - ${t('lists_updated_at')}: ${formatDateTime(response.data.updatedAt)}` : undefined,
      },
      states.length === 0
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
                FEED_REGISTRY.map((provider) => {
                  const state = states.find((s) => s.id === provider.id);
                  return el('tr', {}, [
                    el('td', {}, [badge(providerStatusLabel(provider, state?.status), providerStatusTone(provider, state?.status))]),
                    el('td', {}, [
                      el('div', { text: provider.name }),
                      el('div', { class: 'faint small', text: provider.updateFrequency }),
                      state?.lastError
                        ? el('div', { class: 'small', style: 'color:var(--vbs-danger)', text: state.lastError })
                        : null,
                    ]),
                    el('td', {}, [
                      el('div', { text: provider.license.id }),
                      el('div', { class: 'faint small', text: provider.license.commercialUseAllowed ? t('common_yes') : t('common_no') }),
                    ]),
                    el('td', { class: 'mono', text: formatNumber(state?.entryCount ?? 0) }),
                    el('td', {}, [
                      el('div', { text: formatRelative(state?.lastSuccessAt ?? null) }),
                      state?.contentHash
                        ? el('div', { class: 'mono faint', title: state.contentHash, text: state.contentHash.slice(0, 16) })
                        : null,
                    ]),
                  ]);
                }),
              ),
            ]),
          ]),
    ),
    card({ title: t('opt_credentials_title'), subtitle: t('opt_credentials_intro') }, renderCredentials(configured)),
  ];
}

function renderCredentials(configured: ReadonlySet<string>): Child {
  const providers = FEED_REGISTRY.filter((p) => p.requiresCredential);
  if (providers.length === 0) return emptyState(t('common_none'));

  return el(
    'div',
    { class: 'stack' },
    providers.map((provider) => {
      const input = el('input', {
        type: 'password',
        class: 'text-input',
        placeholder: t('opt_credential_key'),
        maxlength: 512,
        autocomplete: 'off',
        id: `cred-${provider.id}`,
      });

      return el('div', { class: 'field' }, [
        el('label', { for: `cred-${provider.id}`, text: provider.name }),
        el('span', { class: 'hint', text: provider.exclusionReason ?? provider.notes }),
        badge(configured.has(provider.id) ? t('opt_credential_configured') : t('opt_credential_missing'), configured.has(provider.id) ? 'ok' : 'neutral'),
        el('div', { class: 'row' }, [
          input,
          button({
            label: t('opt_credential_save'),
            onClick: async () => {
              await request('feeds.credential', { providerId: provider.id, key: input.value.trim() });
              input.value = '';
              await renderActiveTab();
            },
          }),
          button({
            label: t('opt_credential_clear'),
            variant: 'ghost',
            onClick: async () => {
              await request('feeds.credential', { providerId: provider.id, key: '' });
              await renderActiveTab();
            },
          }),
        ]),
      ]);
    }),
  );
}

function providerStatusLabel(provider: (typeof FEED_REGISTRY)[number], status: string | undefined): string {
  if (provider.excludedFromProduct) return t('provider_status_excluded_license');
  switch (status) {
    case 'active':
      return t('provider_status_active');
    case 'stale':
      return t('provider_status_stale');
    case 'not_configured':
      return t('provider_status_not_configured');
    case 'error':
      return t('provider_status_error');
    case 'bundled_snapshot':
      return t('provider_status_bundled_snapshot');
    default:
      return t('provider_status_disabled');
  }
}

function providerStatusTone(provider: (typeof FEED_REGISTRY)[number], status: string | undefined): BadgeTone {
  if (provider.excludedFromProduct) return 'danger';
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

// --------------------------------------------------------- tab: diagnostics

async function renderDiagnostics(): Promise<Child[]> {
  const response = await request<DiagnosticsResponse>('rules.diagnostics');
  if (!response.ok) return [errorBox(t(response.messageKey))];

  const d = response.data;
  const caps = d.protection.capabilities;

  return [
    card({ title: t('diag_runtime') }, [
      el('dl', { class: 'kv' }, [
        el('dt', { text: t('diag_runtime_browser') }),
        el('dd', { text: navigator.userAgent.slice(0, 120) }),
        el('dt', { text: t('common_enabled') }),
        el('dd', { text: caps.available ? t('common_yes') : t('common_no') }),
        el('dt', { text: t('metric_observed_blocks') }),
        el('dd', { text: d.observation.apiAvailable ? t('common_yes') : t('common_no') }),
        el('dt', { text: t('metric_observed_blocks_hint') }),
        el('dd', { text: formatNumber(d.observation.observed) }),
        el('dt', { text: t('privacy_storage_usage') }),
        el('dd', { text: `${(d.storage.bytes / 1024).toFixed(0)} KiB / ${(d.storage.quotaBytes / 1024 / 1024).toFixed(0)} MiB (${d.storage.percent}%)` }),
        el('dt', { text: t('resource_psl') }),
        el('dd', { text: `${d.psl.origin} - ${formatNumber(d.psl.ruleCount)}` }),
      ]),
    ]),
    card(
      {
        title: t('diag_rules'),
        actions: button({
          label: t('diag_reapply'),
          onClick: async () => {
            await request('rules.diagnostics', {});
            await renderActiveTab();
          },
        }),
      },
      el('div', { class: 'stack' }, [
        el('div', { class: 'stat-grid' }, [
          statTile({ label: t('diag_rules_installed'), value: formatNumber(d.protection.dynamicRuleCount), tone: 'ok' }),
          statTile({ label: t('diag_rules_budget'), value: formatNumber(d.preview.quota.budget) }),
          statTile({ label: t('diag_rules_dropped'), value: formatNumber(d.preview.droppedForQuota), tone: d.preview.droppedForQuota > 0 ? 'warn' : 'neutral' }),
          statTile({ label: t('diag_rules_duplicates'), value: formatNumber(d.preview.duplicatesRemoved) }),
          statTile({ label: t('diag_rules_rejected'), value: formatNumber(d.preview.rejectedInvalidHost) }),
          statTile({ label: t('resource_allowlist'), value: formatNumber(d.protection.sessionRuleCount) }),
        ]),
        d.preview.truncatedCategories.length > 0
          ? el('p', { class: 'callout', text: `${t('reason_feed_list_truncated')}: ${d.preview.truncatedCategories.join(', ')}` })
          : null,
      ]),
    ),
    card({ title: t('diag_limits_title') }, [
      el('dl', { class: 'kv' }, [
        el('dt', { text: t('diag_limits_dynamic') }),
        el('dd', { class: 'mono', text: formatNumber(caps.limits.dynamicSafe) }),
        el('dt', { text: t('diag_limits_unsafe') }),
        el('dd', { class: 'mono', text: formatNumber(caps.limits.dynamicUnsafe) }),
        el('dt', { text: t('diag_limits_session') }),
        el('dd', { class: 'mono', text: formatNumber(caps.limits.session) }),
        el('dt', { text: t('diag_limits_regex') }),
        el('dd', { class: 'mono', text: '0 / 1000' }),
      ]),
    ]),
    card(
      { title: t('perm_title'), subtitle: t('perm_intro') },
      el(
        'div',
        { class: 'data-table-wrap' },
        [
          el('table', { class: 'data-table' }, [
            el('thead', {}, [el('tr', {}, [el('th', { text: t('lists_status') }), el('th', { text: t('common_more') }), el('th', { text: t('lists_format') })])]),
            el(
              'tbody',
              {},
              d.permissions.map((permission) =>
                el('tr', {}, [
                  el('td', { class: 'mono', text: permission.name }),
                  el('td', {}, [
                    badge(permission.present ? t('perm_present') : t('perm_missing'), permission.present ? 'ok' : 'danger'),
                    el('div', { class: 'small muted', text: t(permission.justificationKey) }),
                  ]),
                  el('td', { class: 'small', text: t('perm_host_access_hint') }),
                ]),
              ),
            ),
          ]),
        ],
      ),
    ),
    card(
      { title: t('diag_integration_title'), subtitle: t('diag_integration_note') },
      el(
        'div',
        { class: 'stack' },
        FEED_REGISTRY.filter((p) => p.excludedFromProduct || p.requiresCredential).map((provider) =>
          el('div', { class: 'callout' }, [
            el('strong', { text: `${provider.name}: ` }),
            el('span', {
              text: provider.excludedFromProduct
                ? `${t('provider_status_excluded_license')} - ${provider.exclusionReason ?? provider.license.name}`
                : `${t('provider_status_not_configured')} - ${provider.notes}`,
            }),
          ]),
        ),
      ),
    ),
  ];
}

// --------------------------------------------------------------- tab: about

async function renderAbout(): Promise<Child[]> {
  const manifest = chrome.runtime.getManifest();

  return [
    card({ title: t('privacy_title'), subtitle: t('privacy_intro') }, [
      el('div', { class: 'privacy-grid' }, [
        el('div', {}, [
          el('h3', { class: 'settings-group-title', text: t('privacy_never_title') }),
          el(
            'ul',
            { class: 'privacy-list' },
            [t('privacy_never'), t('privacy_never_2'), t('privacy_never_3'), t('privacy_never_4'), t('privacy_never_5')].map(
              (label) =>
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
        el('div', {}, [
          el('h3', { class: 'settings-group-title', text: t('privacy_network_title') }),
          el('p', { class: 'small muted', text: t('privacy_network') }),
        ]),
      ]),
    ]),
    card({ title: t('privacy_clear_title'), subtitle: t('privacy_clear_intro') }, [
      el('div', { class: 'stack' }, [
        el('label', { class: 'checkbox-row' }, [
          el('input', { type: 'checkbox', id: 'clr-settings', checked: true }),
          el('span', { text: t('privacy_clear_settings') }),
        ]),
        el('label', { class: 'checkbox-row' }, [
          el('input', { type: 'checkbox', id: 'clr-stats', checked: true }),
          el('span', { text: t('privacy_clear_stats') }),
        ]),
        el('label', { class: 'checkbox-row' }, [
          el('input', { type: 'checkbox', id: 'clr-allowlist', checked: true }),
          el('span', { text: t('privacy_clear_allowlist') }),
        ]),
        el('label', { class: 'checkbox-row' }, [
          el('input', { type: 'checkbox', id: 'clr-history', checked: true }),
          el('span', { text: t('privacy_clear_history') }),
        ]),
        el('label', { class: 'checkbox-row' }, [
          el('input', { type: 'checkbox', id: 'clr-threat', checked: false }),
          el('span', { text: t('privacy_clear_threat') }),
        ]),
        el('div', { class: 'row' }, [
          button({
            label: t('privacy_clear_all'),
            variant: 'danger',
            onClick: async (event) => {
              const target = event.currentTarget as HTMLButtonElement;
              target.disabled = true;
              const scope = {
                settings: checked('clr-settings'),
                statistics: checked('clr-stats'),
                allowlist: checked('clr-allowlist'),
                history: checked('clr-history'),
                threatData: checked('clr-threat'),
              };
              await request('data.clear', scope);
              target.disabled = false;
              await renderActiveTab();
            },
          }),
        ]),
      ]),
    ]),
    card({ title: t('privacy_limits_title'), subtitle: t('privacy_limits_intro') }, [
      el('p', { class: 'small muted', text: t('privacy_limits_body') }),
    ]),
    card({ title: t('about_title') }, [
      el('dl', { class: 'kv' }, [
        el('dt', { text: t('about_version') }),
        el('dd', { class: 'mono', text: manifest.version ?? '1.0.0' }),
        el('dt', { text: t('about_license') }),
        el('dd', { text: 'VOLTRIS proprietary. Third-party components under their own licences.' }),
        el('dt', { text: t('about_third_party') }),
        el('dd', { class: 'small', text: t('about_attribution') }),
        el('dt', { text: t('privacy_policy_link') }),
        el('dd', {}, [
          el('a', { href: 'PRIVACY.md', target: '_blank', rel: 'noreferrer noopener', text: 'PRIVACY.md' }),
        ]),
      ]),
    ]),
  ];
}

function checked(id: string): boolean {
  const node = document.getElementById(id);
  return node instanceof HTMLInputElement ? node.checked : false;
}

// ------------------------------------------------------------------ shared

function segmented(
  options: { value: string; label: string }[],
  current: string,
  onPick: (value: string) => void,
): HTMLElement {
  const group = el('div', { class: 'segmented', role: 'group' });
  for (const option of options) {
    const btn = el('button', {
      type: 'button',
      text: option.label,
      'aria-pressed': String(option.value === current),
    });
    btn.addEventListener('click', () => {
      for (const child of Array.from(group.children)) child.setAttribute('aria-pressed', 'false');
      btn.setAttribute('aria-pressed', 'true');
      onPick(option.value);
    });
    group.appendChild(btn);
  }
  return group;
}

const TABS: Tab[] = [
  { id: 'web', labelKey: 'tab_web_protection', render: renderWeb },
  { id: 'phishing', labelKey: 'tab_phishing', render: renderPhishing },
  { id: 'privacy', labelKey: 'tab_privacy', render: renderPrivacyTab },
  { id: 'downloads', labelKey: 'tab_downloads', render: renderDownloadsTab },
  { id: 'sites', labelKey: 'tab_sites', render: renderSites },
  { id: 'updates', labelKey: 'tab_updates', render: renderUpdates },
  { id: 'diagnostics', labelKey: 'tab_diagnostics', render: renderDiagnostics },
  { id: 'about', labelKey: 'tab_about', render: renderAbout },
];

function buildNav(): void {
  if (!navSlot) return;
  clear(navSlot);
  for (const tab of TABS) {
    const btn = el('button', {
      type: 'button',
      role: 'tab',
      id: `tab-${tab.id}`,
      text: t(tab.labelKey),
      'aria-selected': String(tab.id === activeTab),
    });
    btn.addEventListener('click', () => {
      activeTab = tab.id;
      void renderActiveTab();
    });
    navSlot.appendChild(btn);
  }
}

async function renderActiveTab(): Promise<void> {
  if (!panelSlot || !navSlot) return;
  const tab = TABS.find((x) => x.id === activeTab) ?? TABS[0]!;

  for (const child of Array.from(navSlot.children)) {
    child.setAttribute('aria-selected', String(child.id === `tab-${tab.id}`));
  }

  clear(panelSlot);
  append(panelSlot, spinner(t('common_loading')));
  const content = await tab.render();
  clear(panelSlot);
  append(panelSlot, el('div', { class: 'page-panel', id: `panel-${tab.id}`, role: 'tabpanel' }, content));
}

async function init(): Promise<void> {
  const settings = await getSettings();
  await loadUiLanguage(settings.uiLanguage);
  applyTheme(settings.theme, settings.reducedMotion);

  const heading = document.getElementById('settings-heading');
  const subtitle = document.getElementById('settings-subtitle');
  const footer = document.getElementById('settings-footer');
  const logoSlot = document.getElementById('logo-slot');
  const themeSlot = document.getElementById('theme-slot');
  const dashboardBtn = document.getElementById('open-dashboard');

  if (heading) heading.textContent = t('settings_title');
  if (subtitle) subtitle.textContent = t('app_tagline');
  if (footer) footer.textContent = `${t('extension_name')} - ${t('about_attribution')}`;
  if (logoSlot) append(logoSlot, logo(30));
  if (themeSlot) {
    append(
      themeSlot,
      segmented(
        [
          { value: 'system', label: t('theme_system') },
          { value: 'light', label: t('theme_light') },
          { value: 'dark', label: t('theme_dark') },
        ],
        settings.theme,
        (value) => patch({ theme: value as Settings['theme'] }),
      ),
    );
  }
  dashboardBtn?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  });

  buildNav();
  await renderActiveTab();
}

void init();
