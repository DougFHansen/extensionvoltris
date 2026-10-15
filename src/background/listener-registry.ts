/**
 * Registry of the listeners that actually registered.
 *
 * Kept in its own module so `listeners.ts` and `messages.ts` do not have to
 * import each other (the diagnostics surface reads this, the listener surface
 * writes it, and a cycle between two modules that both matter is avoidable).
 */
const registered: string[] = [];
const unavailable: string[] = [];

export interface ListenerStatus {
  readonly registered: readonly string[];
  readonly unavailable: readonly string[];
}

export function markRegistered(name: string): void {
  if (!registered.includes(name)) registered.push(name);
}

export function markUnavailable(name: string): void {
  if (!unavailable.includes(name)) unavailable.push(name);
}

export function listenerStatus(): ListenerStatus {
  return { registered, unavailable };
}
