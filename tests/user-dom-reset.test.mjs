// web/index.html resetUserDom(): what one user's session rendered is cleared
// on sign-out and on any user change, including tabs the new user has not
// opened yet (their DOM used to keep the previous user's panels).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { HTML } from './helpers/chat-harness.mjs';

const fnSrc = (name) => {
  const a = HTML.indexOf(`function ${name}(`);
  let i = HTML.indexOf('{', a), depth = 0;
  for (; i < HTML.length; i++) { if (HTML[i] === '{') depth++; else if (HTML[i] === '}' && --depth === 0) break; }
  return HTML.slice(a, i + 1);
};
const HOSTS = ['#body-vineyard', '#body-winery', '#f-vineyard', '#f-winery', '#queue-list', '#accounts-list', '#keys-once', '#keys-create', '#keys-table'];

test('resetUserDom clears every per-user host, a one-time key, and forces a re-render', () => {
  const els = Object.fromEntries(HOSTS.map((h) => [h, { innerHTML: `<div class="panel" data-panel-id="cellart">operator data ${h}</div>` }]));
  const calls = [];
  const ctx = { $: (s) => els[s] ?? null, hideTip: () => calls.push('hideTip'), unsubscribeOverviewRealtime: () => calls.push('unsub'),
    clearOneTimeKey: () => calls.push('clearKey'), dashboardBooted: true };
  vm.createContext(ctx);
  vm.runInContext(fnSrc('resetUserDom') + '; resetUserDom();', ctx);
  for (const h of HOSTS) assert.equal(els[h].innerHTML, '', h);
  assert.deepEqual(calls.sort(), ['clearKey', 'hideTip', 'unsub']);
  assert.equal(ctx.dashboardBooted, false);
});

test('runSessionGate calls it on sign-out and on any user change, before any role branch', () => {
  const gate = fnSrc('runSessionGate');
  assert.match(gate, /if\(!session\)\{ resetChat\(\); resetUserDom\(\);/);
  assert.match(gate, /if\(session\.user\.id !== chatUserId\)\{ resetChat\(\); resetUserDom\(\);/);
  assert.ok(gate.indexOf('resetUserDom()') < gate.indexOf("role==='pending'"));
});
