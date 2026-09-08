import type Anthropic from "@anthropic-ai/sdk";
import { TOOLS } from "./tools.ts";

// Kimi K3 on Fireworks AI. Fireworks' inference API is OPENAI-compatible, not
// Anthropic-compatible, so this is a real adapter and not a base-URL swap:
// tool schemas nest differently, tool CALLS come back as `tool_calls` with
// stringified JSON arguments instead of `tool_use` blocks, tool RESULTS are
// their own `role:"tool"` messages instead of blocks inside a user turn, and
// the system prompt is a message rather than a top-level field.
//
// The canonical conversation format in this app stays ANTHROPIC-shaped
// throughout -- web/index.html holds `chatHistory` in that shape and replays it
// verbatim on every request (the function is stateless), and `appended` is
// handed straight back into it. So this module translates Anthropic -> OpenAI
// on the way in and OpenAI -> Anthropic on the way out, and the frontend never
// learns which backend answered. That also keeps the flag-off path
// byte-identical to what ships today.

// Confirmed live against GET /inference/v1/models with this project's real
// KIMI_API_KEY: the standard id is `accounts/fireworks/models/kimi-k3` (note
// the `/models/` segment -- `accounts/fireworks/kimi-k3` does NOT resolve),
// and the latency-optimised router is `accounts/fireworks/routers/kimi-k3-fast`.
// Both report supports_tools:true and a 1,048,576-token context window.
export const KIMI_MODEL = "accounts/fireworks/models/kimi-k3";
export const KIMI_BASE_URL = "https://api.fireworks.ai/inference/v1";

// Fireworks' own docs warn that the Kimi K2/K3 family "can produce very long
// reasoning traces" and to "always set max_tokens explicitly". That warning is
// NOT boilerplate for this app: docs/SECURITY.md records a measured incident
// where claude-sonnet-5's adaptive thinking consumed an entire max_tokens
// budget before writing any answer text, and raising max_tokens made it worse.
// See docs/SECURITY.md's Kimi entry for what the same measurement found here.
export const KIMI_MAX_TOKENS = 4000;

interface OpenAITool {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

export interface OpenAIMessage {
  role: "system" | "user" | "assistant" | "tool";
  content?: string | null;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
}

export interface OpenAIToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

// Anthropic puts the JSON Schema under `input_schema` at the top level of the
// tool; OpenAI nests the whole tool under `function` and calls the schema
// `parameters`. The schema BODY is compatible as written -- every property in
// TOOLS uses plain `type`/`description`/`enum`, all of which mean the same
// thing on both sides -- so the translation is structural only and the
// descriptions the model actually reads are passed through unchanged.
//
// Deliberately NOT emitting `strict: true`. OpenAI's strict function calling
// requires `additionalProperties:false` and EVERY property listed in
// `required`, which would misdescribe this tool set: get_series' `block`,
// `vintage` and `agg` are genuinely optional, and forcing the model to supply
// them would change behaviour rather than just tighten validation.
export function toOpenAITools(tools: Anthropic.Tool[] = TOOLS): OpenAITool[] {
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description ?? "",
      parameters: {
        type: "object",
        properties: t.input_schema.properties ?? {},
        // Anthropic tolerates `required` being absent; OpenAI-compatible
        // servers vary, so always emit it (possibly empty).
        required: t.input_schema.required ?? [],
      },
    },
  }));
}

// Anthropic's assistant turn is a list of content blocks; OpenAI's is one
// message with optional `tool_calls`. Anthropic's tool RESULTS ride inside a
// `user` turn as `tool_result` blocks; OpenAI wants one `role:"tool"` message
// per result. So a single Anthropic message can fan out to several OpenAI ones.
//
// `tool_use.input` is a real object on Anthropic and a JSON *string* on OpenAI
// -- the one place where a silent type mismatch would produce a request the
// server accepts and the model then misreads.
export function toOpenAIMessages(
  system: string,
  messages: Anthropic.MessageParam[],
): OpenAIMessage[] {
  const out: OpenAIMessage[] = [{ role: "system", content: system }];

  for (const m of messages) {
    if (typeof m.content === "string") {
      out.push({ role: m.role, content: m.content });
      continue;
    }

    const text: string[] = [];
    const toolCalls: OpenAIToolCall[] = [];
    const toolResults: OpenAIMessage[] = [];

    for (const block of m.content) {
      if (block.type === "text") {
        text.push(block.text);
      } else if (block.type === "tool_use") {
        toolCalls.push({
          id: block.id,
          type: "function",
          function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
        });
      } else if (block.type === "tool_result") {
        toolResults.push({
          role: "tool",
          tool_call_id: block.tool_use_id,
          content: typeof block.content === "string"
            ? block.content
            : JSON.stringify(block.content ?? ""),
        });
      }
      // `thinking`/`redacted_thinking` blocks are dropped on purpose: they are
      // Anthropic-signed artefacts with no OpenAI equivalent, and replaying
      // them to a different provider would be meaningless at best. Kimi's own
      // reasoning arrives in a separate `reasoning_content` field, which this
      // module deliberately does not persist either (see fromOpenAIMessage).
    }

    if (m.role === "assistant") {
      // An assistant turn with no text and no tool calls has nothing to say to
      // the API and some OpenAI-compatible servers reject it, so skip it.
      if (text.length || toolCalls.length) {
        out.push({
          role: "assistant",
          content: text.join("") || null,
          ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        });
      }
    } else {
      // Tool results must come BEFORE any plain user text in the same turn, so
      // every tool_call_id is answered before the next user message opens.
      out.push(...toolResults);
      if (text.length) out.push({ role: "user", content: text.join("") });
    }
  }

  return out;
}

// The reverse trip: an OpenAI choice becomes the Anthropic-shaped content block
// array the rest of index.ts (and the frontend's replayed history) expects.
// `reasoning_content` is deliberately discarded rather than turned into a text
// block -- it is the model's scratchpad, not its answer, and surfacing it would
// change what users see purely because of which backend served the turn.
export function fromOpenAIMessage(
  message: { content?: string | null; tool_calls?: OpenAIToolCall[] | null },
): Anthropic.ContentBlockParam[] {
  const blocks: Anthropic.ContentBlockParam[] = [];
  if (message.content) blocks.push({ type: "text", text: message.content });
  for (const call of message.tool_calls ?? []) {
    let input: Record<string, unknown> = {};
    try {
      input = call.function.arguments ? JSON.parse(call.function.arguments) : {};
    } catch {
      // A malformed arguments string is the model's error, not a transport
      // failure. Passing {} through lets tools.ts' own input validation return
      // a normal is_error tool_result -- the same path index.ts already relies
      // on for a truncated Anthropic tool_use block -- instead of throwing and
      // killing the stream.
      console.error("kimi: could not parse tool arguments", call.function.name);
    }
    blocks.push({ type: "tool_use", id: call.id, name: call.function.name, input });
  }
  return blocks;
}

// OpenAI's finish_reason vocabulary mapped onto the stop_reason values
// index.ts' loop already branches on, so the loop needs no provider awareness:
//   tool_calls -> "tool_use"   length -> "max_tokens"   stop -> "end_turn"
export function toStopReason(finishReason: string | null | undefined): string {
  if (finishReason === "tool_calls") return "tool_use";
  if (finishReason === "length") return "max_tokens";
  return "end_turn";
}

export interface KimiTurn {
  content: Anthropic.ContentBlockParam[];
  stopReason: string;
  usage: {
    // NOTE the semantics, which differ from Anthropic's and will silently
    // double-count if conflated. OpenAI's `prompt_tokens` is the TOTAL prompt
    // including anything served from cache, and `cached` is a SUBSET of it.
    // Anthropic's `input_tokens` EXCLUDES cache reads/writes -- its three
    // counters are disjoint. `input` below is therefore normalised to
    // Anthropic's meaning (the uncached remainder, billed at full rate) so the
    // two providers' `chat: usage` log lines are directly comparable, with
    // `inputTotal` kept for anyone reconciling against Fireworks' own numbers.
    input: number;
    inputTotal: number;
    output: number;
    reasoning: number;
    cached: number;
  };
}

// Non-streaming on purpose for Phase 1 -- see docs/SECURITY.md for the measured
// reason and the Phase 2 follow-up.
// A single model turn has been measured at up to ~83s on the heaviest question
// (two-vintage comparison, ~57KB of tool results), so the ceiling has to clear
// that by a real margin -- but it cannot be absent. The Anthropic SDK brings
// its own 10-minute timeout and retries; a bare `fetch` has neither, so without
// this an unresponsive upstream would hang the whole SSE stream until the Edge
// runtime killed it, with the browser showing a typing indicator the entire
// time and no `error` event ever sent.
const KIMI_TIMEOUT_MS = 180_000;

export async function callKimi(
  apiKey: string,
  system: string,
  messages: Anthropic.MessageParam[],
  opts: { model?: string; maxTokens?: number } = {},
): Promise<KimiTurn> {
  let res: Response;
  try {
    res = await fetch(`${KIMI_BASE_URL}/chat/completions`, {
      method: "POST",
      signal: AbortSignal.timeout(KIMI_TIMEOUT_MS),
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: opts.model ?? KIMI_MODEL,
        max_tokens: opts.maxTokens ?? KIMI_MAX_TOKENS,
        messages: toOpenAIMessages(system, messages),
        tools: toOpenAITools(),
      }),
    });
  } catch (err) {
    // Named distinctly from a transport failure: index.ts turns any throw here
    // into a generic `error` event, and "which one was it" is only recoverable
    // from this log line.
    if ((err as Error)?.name === "TimeoutError") {
      throw new Error(`Fireworks timed out after ${KIMI_TIMEOUT_MS}ms`);
    }
    throw err;
  }

  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Fireworks ${res.status}: ${detail.slice(0, 500)}`);
  }

  const body = await res.json();
  const choice = body.choices?.[0];
  if (!choice) throw new Error("Fireworks returned no choices");

  const usage = body.usage ?? {};
  const inputTotal = usage.prompt_tokens ?? 0;
  const cached = usage.prompt_tokens_details?.cached_tokens ?? 0;
  return {
    content: fromOpenAIMessage(choice.message ?? {}),
    stopReason: toStopReason(choice.finish_reason),
    usage: {
      input: Math.max(0, inputTotal - cached),
      inputTotal,
      output: usage.completion_tokens ?? 0,
      // Counts only what Kimi put in `reasoning_content`. It does NOT capture
      // reasoning the model writes into `content` instead -- measured to
      // happen on the answer turn of heavy questions, which is exactly the
      // case where this number looks reassuringly small and isn't. See
      // docs/SECURITY.md.
      reasoning: usage.completion_tokens_details?.reasoning_tokens ?? 0,
      cached,
    },
  };
}
