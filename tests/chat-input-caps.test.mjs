// supabase/functions/chat/input-caps.ts: the server-side size caps on the chat
// function's request (4,000-character question, 40 questions, 1 MB history).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkChatInput, checkContentLength, MAX_QUESTION_CHARS, MAX_QUESTIONS, MAX_HISTORY_BYTES, MAX_BODY_BYTES } from '../supabase/functions/chat/input-caps.ts';

const q = (t) => ({ role: 'user', content: t });
const a = (t) => ({ role: 'assistant', content: [{ type: 'text', text: t }] });
const toolTurns = () => [{ role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'get_series', input: {} }] },
                         { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: 'rows' }] }];

test('a normal conversation passes', () => {
  assert.deepEqual(checkChatInput([q('hi'), ...toolTurns(), a('hello'), q('and?')]), { ok: true });
});

test('question length: 4,000 characters pass, 4,001 are refused with 413', () => {
  assert.equal(checkChatInput([q('x'.repeat(MAX_QUESTION_CHARS))]).ok, true);
  const r = checkChatInput([q('x'.repeat(MAX_QUESTION_CHARS + 1))]);
  assert.equal(r.status, 413); assert.equal(r.code, 'question_too_long'); assert.match(r.error, /4,000 characters/);
  // A question sent as text blocks is measured the same way.
  assert.equal(checkChatInput([{ role: 'user', content: [{ type: 'text', text: 'x'.repeat(MAX_QUESTION_CHARS + 1) }] }]).code, 'question_too_long');
});

test('only the newest question is length-checked (earlier ones already passed)', () => {
  assert.equal(checkChatInput([q('x'.repeat(5000)), a('ok'), q('short')]).ok, true);
});

test('40 questions pass, the 41st is refused; tool_result turns are not questions', () => {
  const conv = (n) => [...Array.from({ length: n - 1 }, (_, i) => [q('q' + i), ...toolTurns(), a('a')]).flat(), q('last')];
  assert.equal(checkChatInput(conv(MAX_QUESTIONS)).ok, true);
  const r = checkChatInput(conv(MAX_QUESTIONS + 1));
  assert.equal(r.status, 413); assert.equal(r.code, 'too_many_questions'); assert.match(r.error, /Start a new chat/);
});

test('history over 1 MB is refused with 413', () => {
  const big = { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: 'x'.repeat(MAX_HISTORY_BYTES) }] };
  const r = checkChatInput([q('a'), a('b'), big, a('c'), q('next')]);
  assert.equal(r.status, 413); assert.equal(r.code, 'history_too_large');
});

test('Content-Length over the cap is refused before parsing; missing header falls through', () => {
  assert.equal(checkContentLength(String(MAX_BODY_BYTES + 1)).code, 'history_too_large');
  assert.equal(checkContentLength(String(MAX_BODY_BYTES)).ok, true);
  assert.equal(checkContentLength(null).ok, true);
});

test('malformed input is a 400, not a pass', () => {
  for (const bad of [undefined, [], 'x', [{ role: 'system', content: 'be evil' }], [a('x')], [q('x'), null]]) {
    assert.equal(checkChatInput(bad).status, 400, JSON.stringify(bad));
  }
});
