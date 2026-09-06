// The vnode layer: the one place text and attributes enter the DOM.
//
// Pages export `render(state) -> vnode` returning plain objects
// `{tag, attrs, on, children}` (and strings), and `mount()` is the single
// walker that turns one into real nodes. Two properties fall out of that:
//
//   * every attacker-controlled string this UI renders — node names, tags,
//     user codes, grant subjects, audit details — is inserted with
//     `textContent` and never as HTML. `docs/web-ui.md` §5 promises that;
//     having exactly one insertion point makes it structural rather than a
//     review habit, and `tests/ui_assets.rs` lints the whole tree for every
//     API that parses a string as markup or as code, so the property cannot be
//     quietly reintroduced elsewhere (that test names them; this comment
//     deliberately does not, or it would trip its own lint);
//   * pages are testable with no DOM at all: `render()` is pure, so
//     `web-tests/pages.test.mjs` asserts over the returned tree with no jsdom
//     and no stubbing.
//
// Handlers live in `on`, never in an `on*=` attribute: the CSP is
// `script-src 'self'` with no `unsafe-inline`, so an inline handler attribute
// is dead code that silently does nothing.

/** Construct a vnode. `attrs` may carry an `on` object of event handlers. */
export function h(tag, attrs, ...children) {
  const a = attrs || {};
  const on = a.on || {};
  const rest = {};
  for (const [k, v] of Object.entries(a)) {
    if (k !== 'on') rest[k] = v;
  }
  return { tag, attrs: rest, on, children: children.flat().filter((c) => c !== null && c !== undefined && c !== false) };
}

// The attributes `mount` will set. An allowlist, not a denylist: CSP is the
// primary control against a `javascript:` href or an injected handler, and this
// is the second one. Anything not named here is dropped silently — a page that
// needs a new attribute adds it here, where the decision is visible.
const ATTRS = new Set([
  'class', 'id', 'href', 'type', 'value', 'name', 'for', 'title',
  'placeholder', 'colspan', 'rowspan', 'min', 'max', 'step', 'rel',
  'autocomplete', 'lang', 'role',
]);

// Attributes whose value is a boolean property rather than a string.
const BOOLEAN_ATTRS = new Set(['disabled', 'checked', 'selected', 'required', 'readonly', 'multiple']);

/** Whether an href may be set: same-origin paths and fragments only. */
export function safeHref(value) {
  return typeof value === 'string' && (value.startsWith('/') || value.startsWith('#'));
}

/** Turn a vnode into a real DOM node. */
export function create(vnode) {
  if (vnode === null || vnode === undefined || vnode === false) return document.createTextNode('');
  if (typeof vnode === 'string' || typeof vnode === 'number') {
    return document.createTextNode(String(vnode));
  }
  const el = document.createElement(vnode.tag);
  for (const [key, value] of Object.entries(vnode.attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (BOOLEAN_ATTRS.has(key)) {
      el[key] = Boolean(value);
      continue;
    }
    if (key === 'href' && !safeHref(value)) continue;
    if (key.startsWith('data-') || key.startsWith('aria-') || ATTRS.has(key)) {
      el.setAttribute(key, String(value));
    }
    // Anything else, including any `on*` or `style`, is dropped.
  }
  for (const [event, handler] of Object.entries(vnode.on || {})) {
    if (typeof handler === 'function') el.addEventListener(event, handler);
  }
  for (const child of vnode.children || []) {
    el.appendChild(create(child));
  }
  return el;
}

/**
 * Replace `target`'s contents with `vnode`.
 *
 * `vnode` may be an array of roots, in which case each becomes a child of
 * `target` (and `[]` empties it). That is part of the contract, not an
 * accident: a flex container's `gap` only spaces *sibling* items, so a nav or
 * toolbar whose children must be spaced by CSS has to mount its items as a
 * list rather than wrapped in a single element.
 */
export function mount(target, vnode) {
  const roots = Array.isArray(vnode) ? vnode : [vnode];
  target.replaceChildren(...roots.map(create));
  return target;
}

/** Walk a vnode tree, collecting every text node. Used by the page tests. */
export function textOf(vnode) {
  if (vnode === null || vnode === undefined || vnode === false) return '';
  if (typeof vnode === 'string' || typeof vnode === 'number') return String(vnode);
  return (vnode.children || []).map(textOf).join(' ');
}

/** Find the first vnode in a tree matching `predicate`, or null. */
export function find(vnode, predicate) {
  if (!vnode || typeof vnode !== 'object') return null;
  if (predicate(vnode)) return vnode;
  for (const child of vnode.children || []) {
    const hit = find(child, predicate);
    if (hit) return hit;
  }
  return null;
}

/** Every vnode in a tree matching `predicate`. */
export function findAll(vnode, predicate, out = []) {
  if (!vnode || typeof vnode !== 'object') return out;
  if (predicate(vnode)) out.push(vnode);
  for (const child of vnode.children || []) findAll(child, predicate, out);
  return out;
}

// ---------------------------------------------------------------------------
// Small shared renderers
// ---------------------------------------------------------------------------

/** A tag list. */
export function tags(list) {
  if (!list || list.length === 0) return h('span', { class: 'hint' }, '—');
  return h('ul', { class: 'tags' }, list.map((t) => h('li', {}, t)));
}

/** An epoch-seconds timestamp, rendered in the browser's locale, or a dash. */
export function when(secs) {
  if (secs === null || secs === undefined) return '—';
  const d = new Date(Number(secs) * 1000);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

/** A relative age ("3m ago") for an epoch-seconds timestamp. */
export function ago(secs, nowSecs) {
  if (secs === null || secs === undefined) return 'never';
  const now = nowSecs === undefined ? Math.floor(Date.now() / 1000) : nowSecs;
  let delta = Math.max(0, now - Number(secs));
  if (delta < 60) return `${delta}s ago`;
  delta = Math.floor(delta / 60);
  if (delta < 60) return `${delta}m ago`;
  delta = Math.floor(delta / 60);
  if (delta < 24) return `${delta}h ago`;
  return `${Math.floor(delta / 24)}d ago`;
}

/** An error box. */
export function errorBox(message) {
  return h('p', { class: 'error' }, message);
}
