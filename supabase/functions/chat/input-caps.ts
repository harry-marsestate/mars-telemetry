// Input caps for the chat function (docs/SECURITY.md, "Floating chat launcher").
// The function is stateless and replays whatever history the browser sends, so
// without these a caller could send any size of question or history to the
// model on every request. web/index.html applies the same limits before
// sending and shows the same messages; these are the enforcement.
//
// "Turns" means questions: user turns that carry the user's own text. A single
// question can add up to 12 messages (6 tool iterations, each an assistant
// tool_use turn plus a user tool_result turn), so counting raw messages would
// end a conversation after three or four questions. The byte cap is the one
// that binds first in practice: one climate series tool result is 35KB+.
export const MAX_QUESTION_CHARS = 4000;
export const MAX_QUESTIONS = 40;
export const MAX_HISTORY_BYTES = 1_000_000;
// The request body also carries modelProvider; a little headroom over the
// history cap so a body at the limit is judged on its history, not rejected
// on Content-Length first.
export const MAX_BODY_BYTES = MAX_HISTORY_BYTES + 16_384;

export type CapResult = { ok: true } | { ok: false; status: 400 | 413; error: string; code: string };

type Msg = { role?: unknown; content?: unknown };

const isQuestion = (m: Msg) =>
  m.role === "user" &&
  (typeof m.content === "string" ||
    (Array.isArray(m.content) && m.content.some((b) => (b as { type?: unknown })?.type === "text")));

function questionText(m: Msg): string {
  if (typeof m.content === "string") return m.content;
  if (!Array.isArray(m.content)) return "";
  return m.content
    .filter((b) => (b as { type?: unknown })?.type === "text")
    .map((b) => String((b as { text?: unknown }).text ?? ""))
    .join("");
}

// Checked before the body is parsed: a Content-Length over the cap is refused
// without reading it. A missing header (chunked upload) falls through to the
// parsed-size check below.
export function checkContentLength(header: string | null): CapResult {
  const n = header == null ? NaN : Number(header);
  if (Number.isFinite(n) && n > MAX_BODY_BYTES) {
    return { ok: false, status: 413, code: "history_too_large", error: "This conversation has grown too long to continue. Start a new chat to keep going." };
  }
  return { ok: true };
}

export function checkChatInput(messages: unknown): CapResult {
  if (!Array.isArray(messages) || messages.length === 0) {
    return { ok: false, status: 400, code: "bad_request", error: "messages required" };
  }
  for (const m of messages as Msg[]) {
    if (!m || typeof m !== "object" || (m.role !== "user" && m.role !== "assistant")) {
      return { ok: false, status: 400, code: "bad_request", error: "messages must be user or assistant turns" };
    }
  }
  const last = messages[messages.length - 1] as Msg;
  if (!isQuestion(last)) {
    return { ok: false, status: 400, code: "bad_request", error: "the last message must be the user's question" };
  }
  if (questionText(last).length > MAX_QUESTION_CHARS) {
    return { ok: false, status: 413, code: "question_too_long", error: `That question is too long. Keep it under ${MAX_QUESTION_CHARS.toLocaleString("en-US")} characters.` };
  }
  if ((messages as Msg[]).filter(isQuestion).length > MAX_QUESTIONS) {
    return { ok: false, status: 413, code: "too_many_questions", error: `This conversation has reached ${MAX_QUESTIONS} questions. Start a new chat to keep going.` };
  }
  if (new TextEncoder().encode(JSON.stringify(messages)).length > MAX_HISTORY_BYTES) {
    return { ok: false, status: 413, code: "history_too_large", error: "This conversation has grown too long to continue. Start a new chat to keep going." };
  }
  return { ok: true };
}
