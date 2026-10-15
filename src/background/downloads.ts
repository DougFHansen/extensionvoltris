/**
 * Download protection.
 *
 * Capability notes surfaced in the UI:
 *  - `chrome.downloads.onDeterminingFilename` runs BEFORE the file is written,
 *    which is the only place where cancellation is reliable.
 *  - We never read file contents, never touch local files outside the browser's
 *    download API, and never disable the browser's own download protections.
 */
import type { DownloadAnalysis } from '../core/types';
import { analyzeDownload } from '../security/downloads';
import { recordDownload } from '../data/stats';
import { recordHistory } from '../data/history';
import { allowlistDomainSet, getAllowlist } from '../data/allowlist';
import { getSettings } from '../data/settings';
import { flushPendingWrites } from '../data/caches';

export const DOWNLOAD_LISTS = {
  /** Executable and script extensions we surface as informational warnings. */
  executable: [
    'exe', 'msi', 'msix', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'vbe',
    'js', 'jse', 'ws', 'wsh', 'ps1', 'psm1', 'jar', 'reg', 'lnk', 'hta',
    'cpl', 'dll', 'sys', 'apk', 'dmg', 'pkg', 'deb', 'rpm', 'sh',
  ],
  /** Archive formats commonly used to hide a payload. */
  archives: ['zip', 'rar', '7z', 'tar', 'gz', 'iso', 'cab'],
} as const;

export function registerDownloadListeners(): void {
  chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
    void handleDeterminingFilename(item, suggest);
  });

  chrome.downloads.onCreated.addListener((item) => {
    // The filename is not final yet on `onCreated`; the authoritative analysis
    // happens in `onDeterminingFilename`.
    void item;
  });
}

async function handleDeterminingFilename(
  item: chrome.downloads.DownloadItem,
  suggest: (suggestion: chrome.downloads.FilenameSuggestion) => void,
): Promise<void> {
  const settings = await getSettings();
  if (!settings.protectionEnabled || !settings.downloadProtection) {
    suggest({ filename: item.filename, conflictAction: 'uniquify' });
    return;
  }

  const filename = basename(item.filename);
  const analysis = await analyzeDownload(
    {
      filename,
      referrer: item.referrer,
      url: item.url,
    },
    {
      settings,
      allowlisted: allowlistDomainSet(await getAllowlist()),
      warnDangerousExtensions: settings.warnDangerousExtensions,
      warnDoubleExtensions: settings.warnDoubleExtensions,
      downloadAction: settings.downloadAction,
    },
  );

  if (analysis.verdict === 'safe') {
    suggest({ filename: item.filename, conflictAction: 'uniquify' });
    return;
  }

  recordDownload(analysis.verdict, false);
  if (settings.storeHistory) {
    await recordHistory({
      kind: 'download_flagged',
      domain: analysis.sourceDomain ?? '',
      providerId: `verdict:${analysis.verdict}`,
      storeFullUrls: settings.storeFullUrls,
    });
  }

  if (analysis.cancellable) {
    // Cancelling here is supported and safe: the download has not been written
    // to disk yet because we are inside onDeterminingFilename.
    try {
      await chrome.downloads.cancel(item.id);
      recordDownload(analysis.verdict, true);
    } catch {
      // Cancelling can legitimately fail if the download already completed.
      // We fall through to the notification instead.
    }
  }

  if (settings.showNotifications) notify(analysis);
  await flushPendingWrites();

  suggest({ filename: item.filename, conflictAction: 'uniquify' });
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

function notify(analysis: DownloadAnalysis): void {
  const reasons = analysis.reasons
    .filter((r) => r.weight > 0)
    .slice(0, 3)
    .map((r) => messageForReason(r.code))
    .join(' ');

  chrome.notifications
    .create(`vbs-dl-${Date.now().toString(36)}`, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('assets/icons/icon-128.png'),
      title: messageForVerdict(analysis.verdict),
      message: `${analysis.filename}\n${reasons}`,
      priority: analysis.verdict === 'dangerous' ? 2 : 1,
      requireInteraction: analysis.verdict === 'dangerous',
    })
    .catch(() => undefined);
}

function messageForVerdict(verdict: DownloadAnalysis['verdict']): string {
  switch (verdict) {
    case 'dangerous':
      return chrome.i18n.getMessage('download_alert_dangerous');
    case 'caution':
      return chrome.i18n.getMessage('download_alert_caution');
    default:
      return chrome.i18n.getMessage('download_alert_safe');
  }
}

function messageForReason(code: DownloadAnalysis['reasons'][number]['code']): string {
  switch (code) {
    case 'downloads.double_extension':
      return chrome.i18n.getMessage('reason_download_double_extension');
    case 'downloads.dangerous_extension':
      return chrome.i18n.getMessage('reason_download_dangerous_extension');
    case 'downloads.from_known_malicious':
      return chrome.i18n.getMessage('reason_download_from_malicious');
    default:
      return '';
  }
}
