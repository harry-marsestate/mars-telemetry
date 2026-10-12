// The floating chat window and the Chat tab are two views of ONE
// conversation (web/index.html §8). Loads the chat section into a Node vm
// (tests/helpers/chat-harness.mjs) with a scripted SSE stream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HTML, loadChat, sseStream, tick } from './helpers/chat-harness.mjs';

const EXPORT = `globalThis.__t = {
  get history(){ return chatHistory; }, get msgs(){ return chatMsgs; }, get draft(){ return chatDraft; },
  get busy(){ return chatBusy; }, get unread(){ return chatUnread; }, get cwOpen(){ return cwOpen; },
  get cwRoot(){ return cwRoot; }, get cwView(){ return cwView; }, get views(){ return chatViews; },
  set ctxMode(v){ cwCtxMode = v; }, set role(v){ chatRole = v; }, set access(v){ cwBlocksAccess = v; },
  ask, resetChat, newChat, cwOpenWin, cwClose, cwAskAbout, cwPageContext, cwContextForSend, chatSyncViews,
  chatOnLogClick, chatMsgHtml, LOG };`;

const PANELS = [
  { id: 'soilmoist', tab: 'vineyard', minRole: 'all', title: 'Soil moisture', range: '30D' },
  { id: 'irrig', tab: 'vineyard', minRole: 'operator', title: 'Irrigation volume applied', range: '30D' },
  { id: 'cellart', tab: 'winery', minRole: 'operator', title: 'Cellar temperature', range: '5D' },
];

function setup({ role = 'operator', transform, from } = {}) {
  const streams = [];
  const state = { tab: 'vineyard', vineyard: { vintages: [2026], blocks: ['B2'] }, winery: { vintages: [2026], blocks: [] }, range: {}, scrollDays: {} };
  const ALL_IDS = ['B1', 'B2', 'B3'];
  const h = loadChat({
    extra: EXPORT, transform, from,
    invoke: async (name, opts) => {
      if (opts.signal?.aborted) throw new Error('aborted');
      const s = sseStream(); streams.push(s); return { data: s, error: null };
    },
    globals: {
      state, PANELS, ALL_IDS, FIRST_VINTAGE: 2022, CURRENT: 2026,
      selB: (tab) => (state[tab].blocks.length ? state[tab].blocks : [...ALL_IDS]),
      selV: (tab) => [...state[tab].vintages].sort((a, b) => a - b),
    },
  });
  const t = h.ctx.__t;
  t.role = role;
  return { ...h, t, state, streams, last: () => streams[streams.length - 1] };
}
const type = (view, text) => { view.input.value = text; view.input.listeners.input.forEach((f) => f()); };
const finish = (s, text = 'Answer.') => { s.push({ type: 'text', text }); s.push({ type: 'done', appended: [{ role: 'assistant', content: text }], provider: 'claude' }); s.end(); };
// chatOnLogClick resolves the message via the button's .msg ancestor:
const clickOn = (t, view, act, msg) => t.chatOnLogClick({ target: { closest: () => ({ dataset: { act }, closest: () => ({ dataset: { id: String(msg.id) } }) }) } }, view);

test('the window is not built until first opened, and nothing is requested', () => {
  const { t, calls } = setup();
  assert.equal(t.cwRoot, null);
  assert.equal(t.views.length, 1, 'only the Chat tab view exists');
  assert.equal(calls.length, 0);
});

test('one conversation: asked in the window, streaming continues into the Chat tab, and continues from there', async () => {
  const { t, state, last, calls } = setup();
  t.cwOpenWin();
  type(t.cwView, 'How dry is B2?');
  t.cwView.send.onclick();
  await tick();
  last().push({ type: 'text', text: 'Mid-answer about B2' });
  await new Promise((r) => setTimeout(r, 5));
  assert.match(t.cwView.log.innerHTML, /Mid-answer about B2/);

  // Switch to the Chat tab mid-answer: the same bubble, still streaming.
  state.tab = 'chat'; t.chatSyncViews();
  assert.equal(t.cwView.visible(), false, 'window hidden on the Chat tab');
  assert.match(t.LOG.innerHTML, /How dry is B2\?/);
  assert.match(t.LOG.innerHTML, /Mid-answer about B2/);
  last().push({ type: 'done', appended: [{ role: 'assistant', content: 'Mid-answer about B2' }] }); last().end();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.history.length, 2);

  // Continue in the Chat tab: the request carries the window's turns.
  type(t.views[0], 'And B3?');
  t.views[0].send.onclick();
  await tick();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].opts.body.messages.length, 3);
  assert.equal(calls[1].opts.body.messages[0].content.endsWith('How dry is B2?'), true);
  finish(last());
  await new Promise((r) => setTimeout(r, 5));

  // Back on the data tab, the window shows the Chat tab's question too.
  state.tab = 'vineyard'; t.chatSyncViews();
  assert.match(t.cwView.log.innerHTML, /And B3\?/);
  assert.equal(t.msgs.filter((m) => m.who === 'u').length, 2, 'one thread, no copies');
});

test('minimize keeps the conversation, the unsent draft and the scroll position; streaming survives it', async () => {
  const { t, last, $ } = setup();
  t.cwOpenWin();
  type(t.cwView, 'First question');
  t.cwView.send.onclick();
  await tick();
  type(t.cwView, 'half-typed follow-up');
  assert.equal(t.cwView.shown, true);
  Object.assign(t.cwView.log, { scrollTop: 120, scrollHeight: 1000, clientHeight: 300 });
  t.cwView.log.listeners.scroll.forEach((f) => f());
  t.cwClose(true);
  t.cwView.log.scrollTop = 0; // a hidden scroller can report 0
  t.cwView.log.listeners.scroll.forEach((f) => f());
  assert.equal(t.busy !== null, true, 'request still in flight after minimize');
  finish(last(), 'Landed while minimized.');
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.history.length, 2, 'answer committed while minimized');
  assert.equal(t.unread, true);
  assert.equal($('#cw-dot').hidden, false, 'launcher shows the new-answer dot');
  assert.match($('#cw-launch').getAttribute('aria-label'), /new answer/);

  t.cwOpenWin();
  assert.equal(t.unread, false);
  assert.equal($('#cw-dot').hidden, true);
  assert.equal(t.cwView.input.value, 'half-typed follow-up');
  assert.equal(t.cwView.log.scrollTop, 120, 'scroll position restored, not jumped');
  assert.match(t.cwView.log.innerHTML, /Landed while minimized\./);
});

test('one request at a time across both views', async () => {
  const { t, calls } = setup();
  t.cwOpenWin();
  t.ask('one', { surface: 'widget' });
  await tick();
  t.ask('two', { surface: 'tab' });
  await tick();
  assert.equal(calls.length, 1);
  assert.equal(t.cwView.send.disabled, true);
  assert.equal(t.views[0].send.disabled, true);
});

test('sign-out clears the window too, and closes it', async () => {
  const { t, last } = setup();
  t.cwOpenWin();
  type(t.cwView, 'operator question');
  t.cwView.send.onclick();
  await tick();
  last().push({ type: 'text', text: 'Lot T-7 operator data' });
  await new Promise((r) => setTimeout(r, 5));
  type(t.cwView, 'unsent draft');
  t.resetChat();
  last().push({ type: 'done', appended: [{ role: 'assistant', content: 'x' }] }); last().end();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.cwOpen, false);
  assert.equal(t.history.length, 0);
  assert.equal(t.msgs.length, 0);
  assert.equal(t.cwView.log.innerHTML.includes('operator data'), false);
  assert.equal(t.LOG.innerHTML.includes('operator data'), false);
  assert.equal(t.cwView.input.value, '');
});

test('New chat clears the shared thread in both views and drops a stale answer', async () => {
  const { t, last } = setup();
  t.cwOpenWin();
  t.ask('q', { surface: 'widget' });
  await tick();
  t.newChat();
  finish(last());
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(t.history.length, 0);
  assert.equal(t.msgs.length, 0);
  assert.equal(t.busy, null);
});

test('page context: built only from app state, attached visibly, clearable', async () => {
  const { t, calls, state } = setup({ role: 'customer' });
  assert.equal(t.cwPageContext(null).label, 'Vineyard Data · block B2 · vintage 2026');
  state.range.soilmoist = '30D'; state.scrollDays.soilmoist = 30;
  assert.equal(t.cwPageContext('soilmoist').label, 'Soil moisture (30-day view, scrolled back 30 days) · Vineyard Data · block B2 · vintage 2026');
  // A customer never gets an operator-only panel named, and a panel from
  // another tab or an unknown id is ignored.
  assert.equal(t.cwPageContext('irrig').panelId, null);
  assert.equal(t.cwPageContext('cellart').panelId, null);
  assert.equal(t.cwPageContext('<img src=x>').label.includes('<'), false);
  state.vineyard.vintages = [2026, 1999]; // out of range values are dropped
  assert.equal(t.cwPageContext(null).label.includes('1999'), false);
  state.vineyard.vintages = [2026];

  t.cwOpenWin();
  type(t.cwView, 'Is it dry?');
  t.cwView.send.onclick();
  await tick();
  assert.equal(calls[0].opts.body.messages.at(-1).content, '[Viewing: Vineyard Data · block B2 · vintage 2026]\nIs it dry?');
  assert.match(t.cwView.log.innerHTML, /class="msg-ctx">Vineyard Data · block B2 · vintage 2026</);

  t.ctxMode = 'none';
  assert.equal(t.cwContextForSend(), null);

  // A block-restricted customer is described by the blocks RLS gives them,
  // never wider: "all blocks" selected, B2 accessible -> "block B2".
  state.vineyard.blocks = [];
  assert.match(t.cwPageContext(null).label, /all blocks/);
  t.access = ['B2'];
  assert.match(t.cwPageContext(null).label, /· block B2 ·/);
  state.tab = 'chat';
  assert.equal(t.cwPageContext(null), null, 'nothing attached from the Chat tab');
});

test('operators get operator panels named; Ask about this attaches the panel and prefills without sending', () => {
  const { t, calls } = setup({ role: 'operator' });
  assert.equal(t.cwPageContext('irrig').panelId, 'irrig');
  t.cwAskAbout('soilmoist');
  assert.equal(t.cwOpen, true);
  assert.match(t.draft, /Soil moisture/);
  assert.match(t.cwContextForSend().label, /Soil moisture/);
  assert.equal(calls.length, 0, 'never sent on the user\'s behalf');
  t.cwClose(); type(t.cwView, 'my own words'); t.cwAskAbout('soilmoist');
  assert.equal(t.draft, 'my own words', 'a draft the user typed is kept');
});

test('the window is never a view on the Chat tab', () => {
  const { t, state, ctx } = setup();
  t.cwOpenWin();
  state.tab = 'chat'; t.chatSyncViews();
  assert.equal(t.cwView.visible(), false);
  assert.equal(ctx.document.body.dataset.tab, 'chat');
  assert.match(HTML, /body\[data-tab="chat"\] \.cw-launch, body\[data-tab="chat"\] \.cw-win\{display:none\}/);
  assert.match(HTML, /@media print\{\.cw-launch,\.cw-win,\.p-ask\{display:none!important\}\}/);
});

test('server errors: 413 tells the user to start a new chat, 401 says sign in, network says retry', async () => {
  const cases = [
    [{ status: 413, json: async () => ({ code: 'history_too_large', error: 'This conversation has grown too long to continue. Start a new chat to keep going.' }) }, 'FunctionsHttpError', /grown too long[\s\S]*data-act="new"/],
    [{ status: 401, json: async () => ({}) }, 'FunctionsHttpError', /session has expired[\s\S]*data-act="retry"/],
    [{ status: 429, json: async () => ({}) }, 'FunctionsHttpError', /Too many questions[\s\S]*data-act="retry"/],
    [{ status: 500, json: async () => ({ error: 'could not resolve caller role' }) }, 'FunctionsHttpError', /went wrong[\s\S]*could not resolve caller role[\s\S]*data-act="retry"/],
    [undefined, 'FunctionsFetchError', /Couldn’t reach the assistant/],
  ];
  for (const [context, name, re] of cases) {
    const h = loadChat({ extra: EXPORT, invoke: async () => ({ data: null, error: { name, message: 'x', context } }), globals: { state: { tab: 'chat' } } });
    const t = h.ctx.__t;
    t.chatSyncViews();
    await t.ask('q');
    assert.match(t.LOG.innerHTML, re, name + ' ' + context?.status);
    assert.equal(t.history.length, 0);
  }
});

test('Retry re-sends the same question and context in place of the failure', async () => {
  let n = 0; const streams = [];
  const h = loadChat({ extra: EXPORT, globals: { state: { tab: 'chat' } }, invoke: async () => {
    if (n++ === 0) return { data: null, error: { name: 'FunctionsHttpError', message: 'x', context: { status: 502, json: async () => ({}) } } };
    const s = sseStream(); streams.push(s); return { data: s, error: null };
  } });
  const t = h.ctx.__t;
  t.chatSyncViews();
  await t.ask('retry me', { ctx: { label: 'Vineyard Data · all blocks', panelId: null } });
  const failed = t.msgs.at(-1);
  assert.equal(failed.state, 'error');
  clickOn(t, t.views[0], 'retry', failed);
  await tick();
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[1].opts.body.messages.at(-1).content, '[Viewing: Vineyard Data · all blocks]\nretry me');
  assert.equal(t.msgs.filter((m) => m.who === 'u').length, 1, 'the failed attempt is replaced, not duplicated');
});

test('client caps: over 40 questions or 1 MB is refused before any request', async () => {
  const h = loadChat({ extra: EXPORT + 'globalThis.__setHistory = (x)=>{ chatHistory = x; };', invoke: async () => { throw new Error('should not be called'); }, globals: { state: { tab: 'chat' } } });
  const t = h.ctx.__t;
  h.ctx.__setHistory(Array.from({ length: 40 }, (_, i) => [{ role: 'user', content: 'q' + i }, { role: 'assistant', content: 'a' }]).flat());
  await t.ask('one more');
  assert.equal(h.calls.length, 0);
  assert.match(t.msgs.at(-1).err.text, /reached 40 questions/);
  h.ctx.__setHistory([{ role: 'user', content: 'x'.repeat(1_000_001) }, { role: 'assistant', content: 'a' }]);
  await t.ask('one more');
  assert.equal(h.calls.length, 0);
  assert.match(t.msgs.at(-1).err.text, /grown too long/);
});

test('model and user text is escaped in every view', async () => {
  const { t, last, state } = setup();
  t.cwOpenWin();
  t.ask('<img src=x onerror=alert(1)>', { surface: 'widget' });
  await tick();
  finish(last(), '**bold** <script>alert(1)</script> [link](javascript:alert(1))');
  await new Promise((r) => setTimeout(r, 5));
  state.tab = 'chat'; t.chatSyncViews();
  for (const html of [t.cwView.log.innerHTML, t.LOG.innerHTML]) {
    assert.equal(/<img|<script|href=/.test(html), false);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /<strong>bold<\/strong>/);
  }
});

test('usage events are off by default: no writes, no rating controls', async () => {
  const { t, last } = setup({ from: () => { throw new Error('no chat_events writes while the flag is off'); } });
  t.cwOpenWin();
  t.ask('q', { surface: 'widget' });
  await tick();
  finish(last());
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(/data-act="up"|This was wrong/.test(t.cwView.log.innerHTML), false);
});

test('with events on: text is sent only on a confirmed "This was wrong", after the notice is shown', async () => {
  const rows = [];
  const from = (table) => ({ insert: async (row) => { rows.push({ table, ...row }); return { error: null }; } });
  const { t, last } = setup({ from, transform: (s) => s.replace('const CHAT_EVENTS_ENABLED = false;', 'const CHAT_EVENTS_ENABLED = true;') });
  t.cwOpenWin();
  t.ask('Why did Brix jump?', { surface: 'widget', ctx: { label: 'Winery Data · all blocks', panelId: 'ferm' } });
  await tick();
  finish(last(), 'Brix rose 2.4.');
  await new Promise((r) => setTimeout(r, 5));
  const ans = t.msgs.at(-1);
  assert.deepEqual(rows.map((r) => r.event), ['open', 'ask']);
  assert.equal(rows.some((r) => 'question' in r || 'answer' in r), false);

  clickOn(t, t.cwView, 'up', ans);
  assert.equal(rows.at(-1).event, 'thumb_up');
  assert.equal('question' in rows.at(-1), false);
  clickOn(t, t.cwView, 'down', ans);
  assert.equal(rows.at(-1).event, 'thumb_up', 'one rating per answer');

  clickOn(t, t.cwView, 'flag', ans);
  assert.match(t.cwView.log.innerHTML, /Your question and this answer’s text will be sent to the Mars Estate team/);
  assert.equal(rows.length, 3, 'nothing sent until confirmed');
  clickOn(t, t.cwView, 'flag-cancel', ans);
  clickOn(t, t.cwView, 'flag', ans);
  clickOn(t, t.cwView, 'flag-send', ans);
  await tick();
  const flag = rows.at(-1);
  assert.equal(flag.event, 'flag_wrong');
  assert.equal(flag.question, '[Viewing: Winery Data · all blocks]\nWhy did Brix jump?');
  assert.equal(flag.answer, 'Brix rose 2.4.');
  assert.equal(flag.panel_id, 'ferm');
  assert.equal(flag.turn_index, 0);
  assert.match(t.cwView.log.innerHTML, /Reported — thank you/);
});
