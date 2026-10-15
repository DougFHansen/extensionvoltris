/**
 * Shared UI primitives.
 *
 * SECURITY: every helper in this file creates DOM nodes programmatically and
 * writes text through `textContent`. There is no `innerHTML`, no `insertAdjacentHTML`
 * and no `document.write` anywhere in the UI layer, which structurally removes the
 * DOM XSS surface required by Section 14.
 */

/**
 * Message lookup.
 *
 * Re-exported from `./i18n` so every existing call site keeps importing `t`
 * from this module while the language-override logic lives in one place. It is
 * also imported for local use, because helpers in this file call it directly.
 */
import { translate as t } from './i18n';

export { t };

export type Attrs = Record<string, string | number | boolean | undefined | null>;
export type Child = Node | string | number | null | undefined | false;

/**
 * Creates an element.
 * `text` is always applied via `textContent`; `html` deliberately does not exist.
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Attrs,
  children?: Child | Child[],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') node.className = String(value);
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'dataset') {
        for (const [dk, dv] of Object.entries(value as unknown as Record<string, string>)) {
          node.dataset[dk] = dv;
        }
      } else if (value === true) node.setAttribute(key, '');
      else node.setAttribute(key, String(value));
    }
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children?: Child | Child[]): void {
  if (children === undefined || children === null || children === false) return;
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function replace(node: Element, children: Child | Child[]): void {
  clear(node);
  append(node, children);
}

// ---------------------------------------------------------------- components

export interface CardOptions {
  title?: string;
  subtitle?: string;
  actions?: Child | Child[];
  className?: string;
}

export function card(options: CardOptions, body?: Child | Child[]): HTMLElement {
  const children: Child[] = [];
  if (options.title) {
    children.push(
      el('div', { class: 'card-head' }, [
        el('div', {}, [
          el('h2', { class: 'card-title', text: options.title }),
          options.subtitle ? el('p', { class: 'card-subtitle', text: options.subtitle }) : null,
        ]),
        options.actions ? el('div', { class: 'card-actions' }, options.actions) : null,
      ]),
    );
  }
  children.push(el('div', { class: 'card-body' }, body));
  return el('section', { class: `card ${options.className ?? ''}`.trim() }, children);
}

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

export interface ButtonOptions {
  label: string;
  variant?: ButtonVariant;
  onClick?: (event: MouseEvent) => void | Promise<void>;
  disabled?: boolean;
  type?: 'button' | 'submit';
  title?: string;
  full?: boolean;
}

export function button(options: ButtonOptions): HTMLButtonElement {
  const classes = ['btn', `btn-${options.variant ?? 'secondary'}`];
  if (options.full) classes.push('btn-full');
  const node = el('button', {
    class: classes.join(' '),
    type: options.type ?? 'button',
    ...(options.disabled ? { disabled: true } : {}),
    ...(options.title ? { title: options.title } : {}),
  });
  node.textContent = options.label;
  if (options.onClick) {
    node.addEventListener('click', (event) => {
      // Prevent double submission on slow actions.
      if (node.disabled) return;
      void options.onClick!(event);
    });
  }
  return node;
}

export interface ToggleOptions {
  id: string;
  label: string;
  hint?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void | Promise<void>;
}

export function toggle(options: ToggleOptions): HTMLElement {
  const input = el('input', { type: 'checkbox', id: options.id, class: 'switch-input' });
  input.checked = options.checked;
  if (options.disabled) input.disabled = true;
  input.addEventListener('change', () => {
    void options.onChange(input.checked);
  });

  const label = el('label', { class: 'switch', for: options.id }, [
    el('span', { class: 'switch-track' }, [el('span', { class: 'switch-thumb' })]),
    el('span', { class: 'switch-text' }, [
      el('span', { class: 'switch-label', text: options.label }),
      options.hint ? el('span', { class: 'switch-hint', text: options.hint }) : null,
    ]),
  ]);

  return el('div', { class: 'switch-row' }, [input, label]);
}

export type BadgeTone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral';

export function badge(text: string, tone: BadgeTone = 'neutral'): HTMLElement {
  return el('span', { class: `badge badge-${tone}`, text });
}

export interface StatOptions {
  label: string;
  value: string;
  hint?: string;
  tone?: BadgeTone;
}

export function statTile(options: StatOptions): HTMLElement {
  return el('div', { class: `stat stat-${options.tone ?? 'neutral'}` }, [
    el('span', { class: 'stat-label', text: options.label }),
    el('span', { class: 'stat-value', text: options.value }),
    options.hint ? el('span', { class: 'stat-hint', text: options.hint }) : null,
  ]);
}

export function emptyState(title: string, hint?: string, action?: Child): HTMLElement {
  return el('div', { class: 'empty' }, [
    el('div', { class: 'empty-icon', 'aria-hidden': 'true' }, [shieldGlyph(28)]),
    el('p', { class: 'empty-title', text: title }),
    hint ? el('p', { class: 'empty-hint', text: hint }) : null,
    action ?? null,
  ]);
}

export function spinner(label?: string): HTMLElement {
  return el('div', { class: 'spinner-row', role: 'status', 'aria-live': 'polite' }, [
    el('span', { class: 'spinner', 'aria-hidden': 'true' }),
    label ? el('span', { class: 'spinner-label', text: label }) : null,
  ]);
}

export function errorBox(message: string): HTMLElement {
  return el('div', { class: 'error-box', role: 'alert' }, [
    el('strong', { class: 'error-title', text: t('common_error') }),
    el('span', { class: 'error-text', text: message }),
  ]);
}

/** Inline SVG created via DOM APIs, never via innerHTML. */
export function shieldGlyph(size = 20, tone?: string): SVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (tone) svg.setAttribute('class', tone);

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute(
    'd',
    'M12 2.2 4.4 5.1v5.6c0 4.6 3.1 8.8 7.6 10.1 4.5-1.3 7.6-5.5 7.6-10.1V5.1L12 2.2Z',
  );
  path.setAttribute('fill', 'currentColor');
  path.setAttribute('opacity', '0.16');

  const check = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  check.setAttribute('d', 'M8.1 12.2l2.6 2.6 5.2-5.4');
  check.setAttribute('fill', 'none');
  check.setAttribute('stroke', 'currentColor');
  check.setAttribute('stroke-width', '2');
  check.setAttribute('stroke-linecap', 'round');
  check.setAttribute('stroke-linejoin', 'round');

  svg.append(path, check);
  return svg;
}

export function logo(size = 28): HTMLElement {
  const wrap = el('span', { class: 'logo', 'aria-hidden': 'true' });
  wrap.appendChild(shieldGlyph(size, 'logo-mark'));
  return wrap;
}

// ---------------------------------------------------------------- formatting

export function formatNumber(value: number): string {
  if (!Number.isFinite(value)) return '0';
  return new Intl.NumberFormat(undefined).format(value);
}

export function formatDateTime(timestamp: number | null | undefined): string {
  if (!timestamp || timestamp <= 0) return t('common_never');
  try {
    return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp));
  } catch {
    return new Date(timestamp).toISOString();
  }
}

export function formatRelative(timestamp: number | null | undefined): string {
  if (!timestamp || timestamp <= 0) return t('common_never');
  const deltaSeconds = Math.round((timestamp - Date.now()) / 1000);
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 30],
    ['month', 12],
    ['year', Number.POSITIVE_INFINITY],
  ];
  try {
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    let value = deltaSeconds;
    for (const [unit, size] of units) {
      if (Math.abs(value) < size) return rtf.format(Math.round(value), unit);
      value /= size;
    }
    return rtf.format(Math.round(value), 'year');
  } catch {
    return formatDateTime(timestamp);
  }
}

export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}...${value.slice(value.length - half)}`;
}

/** Displays a URL safely: scheme and hostname only, never the query string. */
export function displayUrl(url: string | null | undefined): string {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'chrome:' || parsed.protocol === 'edge:') return `${parsed.protocol}//`;
    return `${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}`;
  } catch {
    return truncateMiddle(url);
  }
}

// ---------------------------------------------------------------- theming

export function applyTheme(theme: 'system' | 'light' | 'dark', reducedMotion = false): void {
  const root = document.documentElement;
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;
  const effective = theme === 'system' ? (prefersDark ? 'dark' : 'light') : theme;
  root.dataset.theme = effective;
  root.dataset.reducedMotion = reducedMotion ? 'true' : 'false';

  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', effective === 'dark' ? '#0b0f14' : '#f6f7f9');
}

/** Small inline bar chart for the dashboard. No external charting library. */
export function barChart(data: { day: string; count: number }[], height = 96): HTMLElement {
  const max = Math.max(1, ...data.map((d) => d.count));
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${Math.max(1, data.length * 16)} ${height}`);
  svg.setAttribute('class', 'chart');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', t('dash_last_14_days'));

  data.forEach((point, index) => {
    const barHeight = Math.max(2, Math.round((point.count / max) * (height - 6)));
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', String(index * 16 + 3));
    rect.setAttribute('y', String(height - barHeight));
    rect.setAttribute('width', '10');
    rect.setAttribute('height', String(barHeight));
    rect.setAttribute('rx', '2');
    rect.setAttribute('class', point.count > 0 ? 'chart-bar chart-bar-active' : 'chart-bar');
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${point.day}: ${formatNumber(point.count)}`;
    rect.appendChild(title);
    svg.appendChild(rect);
  });

  return el('div', { class: 'chart-wrap' }, [svg]);
}
