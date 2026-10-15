/**
 * Bridge used to (re)inject the content script into a tab on explicit user
 * request. Uses `chrome.scripting.executeScript` with `func`, which injects a
 * self-contained function - no remote script, no eval, and CSP-safe because the
 * code lives in our own bundle.
 */
import { SCAM_SCAN_FUNCTION } from './scam-scan-source';

export async function registerScarcityScan(tabId: number): Promise<boolean> {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || !/^https?:/i.test(tab.url)) return false;
    await chrome.scripting.executeScript({
      target: { tabId },
      func: SCAM_SCAN_FUNCTION,
      world: 'ISOLATED',
    });
    return true;
  } catch {
    // Chrome forbids injection into chrome:// pages, the Web Store and PDFs.
    // We surface that as "not supported on this page" rather than an error.
    return false;
  }
}
