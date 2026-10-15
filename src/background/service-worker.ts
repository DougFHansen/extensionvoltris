/**
 * VOLTRIS Browser Shield - service worker entry point (Manifest V3).
 *
 * Design constraints (Section 11):
 *  - Strictly EVENT DRIVEN. No setInterval, no keep-alive loops, no polling.
 *  - No work is performed at import time beyond wiring listeners.
 *  - All long-running work is guarded by a single-flight lock so a suspension
 *    and resume can never run two update cycles concurrently.
 */
import { installListeners } from './listeners';
import { bootstrap } from './bootstrap';

// The worker is resumed by any registered event; `bootstrap` is idempotent and
// cheap on subsequent calls.
void bootstrap();

installListeners();
