// Loads web/index.html's chat section (§8, up to §9) into a Node vm with a
// minimal fake DOM and a scriptable `sb`, so chat state can be tested without a
// browser. Only what §8 touches is faked; anything else throws loudly.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

export const HTML = readFileSync(new URL('../../web/index.html', import.meta.url), 'utf8');

export function section(startMarker, endMarker) {
  const a = HTML.indexOf(startMarker), b = HTML.indexOf(endMarker, a);
  if (a < 0 || b < 0) throw new Error(`markers not found: ${startMarker} .. ${endMarker}`);
  return HTML.slice(a, b);
}

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag; this.children = []; this._html = ''; this.textContent = '';
    this.style = {}; this.dataset = {}; this.attrs = {}; this.listeners = {}; this.value = '';
    this.scrollTop = 0; this.scrollHeight = 0; this.clientHeight = 0; this.hidden = false;
    this._q = new Map();
    const cls = new Set();
    this.classList = { add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)),
      toggle: (c, on) => { (on ?? !cls.has(c)) ? cls.add(c) : cls.delete(c); }, contains: (c) => cls.has(c) };
  }
  set className(v) { v.split(/\s+/).filter(Boolean).forEach((c) => this.classList.add(c)); }
  get innerHTML() { return this._html + this.children.map((c) => c.innerHTML).join(''); }
  set innerHTML(v) { this._html = String(v); this.children = []; this._q.clear(); }
  appendChild(c) { this.children.push(c); c.parentNode = this; return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(c)); }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); }
  // A queried element is created on first use and becomes a child, so its
  // content shows up in the parent's innerHTML.
  querySelector(s) { if (!this._q.has(s)) this._q.set(s, this.appendChild(new FakeEl())); return this._q.get(s); }
  querySelectorAll() { return []; }
  addEventListener(t, f) { (this.listeners[t] ??= []).push(f); }
  removeEventListener() {}
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] ?? null; }
  removeAttribute(k) { delete this.attrs[k]; }
  focus() {} blur() {} contains() { return false; }
  get textOf() { return (this.textContent || '') + this.innerHTML; }
}

// A controllable SSE body: push(event) / end() / fail(err).
export function sseStream() {
  const queue = []; let waiter = null; let ended = false; let err = null;
  const wake = () => { if (waiter) { const w = waiter; waiter = null; w(); } };
  const enc = new TextEncoder();
  return {
    push(ev) { queue.push(enc.encode(`data: ${JSON.stringify(ev)}\n\n`)); wake(); },
    end() { ended = true; wake(); },
    fail(e) { err = e; wake(); },
    body: { getReader: () => ({
      async read() {
        for (;;) {
          if (queue.length) return { done: false, value: queue.shift() };
          if (err) throw err;
          if (ended) return { done: true, value: undefined };
          await new Promise((r) => { waiter = r; });
        }
      },
      cancel: async () => { ended = true; wake(); },
    }) },
  };
}

export const tick = () => new Promise((r) => setTimeout(r, 0));

// extra: source appended after the chat section (e.g. a test-only export line).
// globals: dashboard state the chat reads at runtime (state, PANELS, ...).
// transform: edits the section source first (e.g. flip a feature flag).
export function loadChat({ extra = '', invoke, from, globals = {}, transform = (s) => s } = {}) {
  const els = new Map();
  const $ = (s) => { if (!els.has(s)) els.set(s, new FakeEl()); return els.get(s); };
  const calls = [];
  const sb = {
    functions: { invoke: (name, opts) => { calls.push({ name, opts }); return invoke(name, opts); } },
    from: from ?? (() => { throw new Error('unexpected sb.from'); }),
  };
  const ctx = {
    $, $$: () => [], sb, console,
    el: (t, c, h) => { const e = new FakeEl(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; },
    escapeHtml: (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    requestAnimationFrame: (f) => setTimeout(f, 0), cancelAnimationFrame: (id) => clearTimeout(id),
    setTimeout, clearTimeout, TextDecoder, TextEncoder, AbortController,
    navigator: { onLine: true }, innerWidth: 1280, innerHeight: 900,
    document: { createElement: (t) => new FakeEl(t), addEventListener() {}, activeElement: null, body: new FakeEl('body') },
    window: {}, matchMedia: () => ({ matches: false, addEventListener() {} }),
    ...globals,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const src = transform(section('/* §8 ── CHAT', '/* §9 ──')) + '\n' + extra;
  vm.runInContext(src, ctx, { filename: 'web/index.html#chat' });
  return { ctx, $, calls, els };
}
