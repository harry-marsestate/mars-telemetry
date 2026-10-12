// A conversation must never be carried from one signed-in user to the next
// (web/index.html §8 resetChat/chatGen, and runSessionGate). chatHistory
// replays raw tool results, so a turn crossing accounts would put one user's
// rows -- operator-only ones included -- into the next user's model context.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HTML, loadChat, sseStream, tick } from './helpers/chat-harness.mjs';

const EXPORT = 'globalThis.__chat = { get history(){ return chatHistory; }, get role(){ return chatRole; }, resetChat, ask, initChat, LOG };';

function harness() {
  let stream;
  const h = loadChat({ extra: EXPORT, invoke: async () => { stream = sseStream(); return { data: stream, error: null }; } });
  return { ...h, chat: h.ctx.__chat, stream: () => stream };
}

test('a completed answer is committed to history (baseline)', async () => {
  const { chat, stream } = harness();
  const p = chat.ask('How is GDD tracking?');
  await tick();
  stream().push({ type: 'text', text: 'On pace.' });
  stream().push({ type: 'done', appended: [{ role: 'assistant', content: 'On pace.' }], provider: 'claude' });
  stream().end();
  await p;
  assert.equal(chat.history.length, 2);
});

test('an answer still streaming at sign-out never lands in the next user\'s history', async () => {
  const { chat, stream, calls } = harness();
  const p = chat.ask('Operator question about lot T-7');
  await tick();
  stream().push({ type: 'text', text: 'Lot T-7 Brix is 24.1' });
  await tick();
  chat.resetChat(); // what runSessionGate does on sign-out / user change
  assert.equal(calls[0].opts.signal.aborted, true, 'in-flight request is aborted');
  // The server finishes anyway (the abort raced it): the late `done` must be dropped.
  stream().push({ type: 'done', appended: [{ role: 'user', content: [{ type: 'tool_result', content: 'operator rows' }] }] });
  stream().end();
  await p;
  assert.equal(chat.history.length, 0);
  assert.equal(chat.LOG.innerHTML, '');
});

test('a request that has not returned yet at sign-out writes nothing', async () => {
  let release;
  const h = loadChat({ extra: EXPORT, invoke: () => new Promise((r) => { release = r; }) });
  const chat = h.ctx.__chat;
  const p = chat.ask('question');
  await tick();
  chat.resetChat();
  const s = sseStream();
  s.push({ type: 'done', appended: [{ role: 'assistant', content: 'A' }] }); s.end();
  release({ data: s, error: null });
  await p;
  assert.equal(chat.history.length, 0);
  assert.equal(chat.LOG.innerHTML, '');
});

test('a greeting still loading for the previous user is not painted for the next', async () => {
  let releaseProfile;
  const from = () => ({ select: () => ({ eq: () => ({ single: () => new Promise((r) => { releaseProfile = r; }) }) }) });
  const h = loadChat({ extra: EXPORT, invoke: async () => ({}), from });
  const chat = h.ctx.__chat;
  const p = chat.initChat({ user: { id: 'A' } }, 'customer');
  await tick();
  chat.resetChat(); // A signs out before the profile read returns
  releaseProfile({ data: { first_name: 'Alice', last_name: 'A' } });
  await p;
  assert.equal(chat.LOG.innerHTML.includes('Alice'), false);
});

test('resetChat clears history, role, draft and suggestions', async () => {
  const { chat, stream, $ } = harness();
  const p = chat.ask('q'); await tick();
  stream().push({ type: 'done', appended: [{ role: 'assistant', content: 'a' }] }); stream().end(); await p;
  $('#chatin').value = 'half-typed operator question';
  $('#chipPanel').innerHTML = '<button>Brix trend for 25CS-B2</button>';
  chat.resetChat();
  assert.equal(chat.history.length, 0);
  assert.equal(chat.role, null);
  assert.equal($('#chatin').value, '');
  assert.equal($('#chipPanel').innerHTML, '');
});

test('runSessionGate resets the chat on sign-out and on any user change', () => {
  const gate = HTML.slice(HTML.indexOf('async function runSessionGate'), HTML.indexOf("$('#pending-signout')"));
  assert.match(gate, /if\(!session\)\{ resetChat\(\); resetUserDom\(\);/);
  assert.match(gate, /if\(session\.user\.id !== chatUserId\)\{ resetChat\(\); resetUserDom\(\); chatUserId=null;/);
});
