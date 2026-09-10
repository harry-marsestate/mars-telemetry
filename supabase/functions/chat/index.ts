import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";
import Anthropic from "@anthropic-ai/sdk";
import { TOOLS, runTool } from "./tools.ts";
import { callKimi, KIMI_MODEL } from "./kimi.ts";

// RAG chat for Mars Estate/Mars Telemetry. ctx.supabase is RLS-scoped to the
// caller's own JWT for every tool call -- deliberately never ctx.supabaseAdmin,
// so a customer or pending user gets exactly the rows their role/RLS policies
// already allow (including zero rows), the same way the rest of the app works.
// Stateless: no conversation history persisted server-side -- the frontend
// sends the full message history every call and appends what we return.
//
// Responds with Server-Sent Events, one JSON object per `data:` line:
//   {type:"text",  text}                    incremental answer text
//   {type:"tool",  text}                    status line before tools run
//   {type:"done",  appended, truncated}     terminal, and the ONLY success signal
//   {type:"error", message}                 failure after streaming began
// A single JSON object per event rather than named SSE `event:` lines: the
// client hand-parses this, and one shape is fewer edge cases than two.
//
// Measured before building this: 39-80% of a reply's wall clock (median 54%)
// happens after the first text token, so streaming hides roughly half the
// perceived wait without changing total generation time. That the Edge runtime
// -- and specifically withSupabase({auth:["user"]}), not just a bare handler --
// passes a ReadableStream through unbuffered was verified against the real auth
// path with a throwaway probe (~1000ms client gaps from a server sleeping
// 1000ms; 401 without a JWT), not assumed.
// Runs Kimi's full tool loop in isolation, buffering every SSE event instead
// of sending it immediately. The hard requirement (docs/SECURITY.md) is that
// an operator on Kimi must never see a blank reply or a max_tokens failure --
// tuning (reasoning_effort:"low", see kimi.ts) makes that rare, not
// impossible, so nothing reaches the browser until the WHOLE attempt (every
// tool iteration) is confirmed to have produced a genuine, complete answer. A
// failure at any point -- truncation, a thrown error, a timeout -- discards
// the buffer entirely; the caller re-runs the same question against Claude
// from scratch. Partial Kimi tool results are deliberately never reused: a
// failed run may have incomplete results, and correctness matters more than
// the extra cost/latency of a clean re-run.
type KimiAttempt =
  | { ok: true; events: Record<string, unknown>[]; appended: Anthropic.MessageParam[] }
  | { ok: false; reason: string };

async function attemptKimi(
  supabase: Parameters<typeof runTool>[0],
  kimiApiKey: string,
  systemPrompt: string,
  conversation: Anthropic.MessageParam[],
  maxIterations: number,
): Promise<KimiAttempt> {
  const events: Record<string, unknown>[] = [];
  const newTurns: Anthropic.MessageParam[] = [];
  let sawText = false;

  try {
    for (let i = 0; i < maxIterations; i++) {
      const turn = await callKimi(kimiApiKey, systemPrompt, [...conversation, ...newTurns]);
      console.log("chat: usage " + JSON.stringify({
        turn: i,
        provider: "kimi",
        model: KIMI_MODEL,
        input: turn.usage.input,
        cache_read: turn.usage.cached,
        cache_write: 0,
        output: turn.usage.output,
        thinking: turn.usage.reasoning,
        stop: turn.stopReason,
      }));

      const content = turn.content;
      const stopReason = turn.stopReason;
      for (const b of content) {
        if (b.type === "text" && b.text) {
          sawText = true;
          events.push({ type: "text", text: b.text });
        }
      }
      newTurns.push({ role: "assistant", content });

      const toolUses = content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");
      if (stopReason === "tool_use" || (stopReason === "max_tokens" && toolUses.length)) {
        const status = describeToolCalls(toolUses);
        if (status) events.push({ type: "tool", text: status });

        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of toolUses) {
          const result = await runTool(supabase, block.name, block.input as Record<string, unknown>);
          toolResults.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: result.content,
            is_error: result.isError,
          });
        }
        newTurns.push({ role: "user", content: toolResults });
        continue;
      }

      // A genuinely terminal turn. max_tokens here (no tool_use left to run)
      // is exactly the answer-turn scratchpad-leak failure docs/SECURITY.md
      // measured -- not something to show the operator, something to recover
      // from via the fallback below.
      if (stopReason === "max_tokens") return { ok: false, reason: "max_tokens" };
      if (!sawText) return { ok: false, reason: "no_text" };
      return { ok: true, events, appended: newTurns };
    }
    return { ok: false, reason: "max_iterations" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: msg.includes("timed out") ? "timeout" : "error" };
  }
}

export default {
  fetch: withSupabase({ auth: ["user"] }, async (req, ctx) => {
    try {
      const { messages, modelProvider } = await req.json();
      if (!Array.isArray(messages) || messages.length === 0) {
        return Response.json({ error: "messages required" }, { status: 400 });
      }

      // Resolved once per request via the same RLS-safe, SECURITY DEFINER
      // RPC the frontend already uses for role display (getCurrentUserRole()).
      // Folding it into the system prompt means the model knows up front
      // whether operator-only tools will return real rows or honest
      // emptiness, instead of discovering it tool-call by tool-call.
      const { data: role, error: roleErr } = await ctx.supabase.rpc("current_role_name");
      if (roleErr) {
        console.error("chat: could not resolve caller role", roleErr);
        return Response.json({ error: "could not resolve caller role" }, { status: 500 });
      }

      // Personalization only -- not fatal if it fails, unlike role resolution above.
      const { data: profile, error: profileErr } = await ctx.supabase
        .from("user_profiles")
        .select("first_name, last_name")
        .maybeSingle();
      if (profileErr) console.error("chat: could not resolve caller profile", profileErr);
      const displayName = resolveDisplayName(role, profile?.first_name ?? null, profile?.last_name ?? null);

      // CHAT_MODEL_PROVIDER is the deploy-time default (unset/anything but
      // "kimi" fails safe onto what ships today). `modelProvider` on the
      // request body is the Phase 2 operator toggle from web/index.html's
      // model dropdown -- but it is client-controlled JSON, so it can only
      // ever SELECT "kimi", never grant it: gated on `role`, the exact same
      // check resolveDisplayName/buildSystemPrompt already use elsewhere in
      // this function, resolved above via the SECURITY DEFINER
      // current_role_name() RPC keyed off auth.uid(), not anything the caller
      // supplied. A customer or pending account crafting
      // `modelProvider:"kimi"` directly against this endpoint still gets
      // "anthropic" -- confirmed live (docs/SECURITY.md), not just reasoned
      // about, since the frontend hides the control but does not enforce it.
      const deployProvider = Deno.env.get("CHAT_MODEL_PROVIDER") === "kimi" ? "kimi" : "anthropic";
      const provider = modelProvider === "kimi" && role === "operator"
        ? "kimi"
        : modelProvider === "claude"
          ? "anthropic"
          : deployProvider;
      const kimiApiKey = Deno.env.get("KIMI_API_KEY");
      if (provider === "kimi" && !kimiApiKey) {
        console.error("chat: CHAT_MODEL_PROVIDER=kimi but KIMI_API_KEY is unset");
        return Response.json({ error: "chat backend is misconfigured" }, { status: 500 });
      }

      const anthropic = new Anthropic({ apiKey: Deno.env.get("ANTHROPIC_API_KEY") });

      const systemPrompt = buildSystemPrompt(role, displayName);
      const conversation: Anthropic.MessageParam[] = messages;
      const newTurns: Anthropic.MessageParam[] = [];

      // Bounds cost/latency on a single chat turn -- six round trips is far
      // more than any legitimate question over this tool set should need.
      const MAX_TOOL_ITERATIONS = 6;

      // Everything above here can still fail as an ordinary JSON error response,
      // because nothing has been streamed yet. Everything below runs inside the
      // stream, where headers are already sent and the only way to report a
      // failure is an `error` event.
      const encoder = new TextEncoder();
      const body = new ReadableStream({
        async start(controller) {
          const send = (event: Record<string, unknown>) =>
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
          let sawText = false;
          let usedFallback = false;

          try {
            if (provider === "kimi") {
              const attempt = await attemptKimi(
                ctx.supabase,
                kimiApiKey as string,
                systemPrompt,
                conversation,
                MAX_TOOL_ITERATIONS,
              );
              if (attempt.ok) {
                for (const e of attempt.events) send(e);
                send({ type: "done", appended: attempt.appended, truncated: false });
                return;
              }

              // Mandatory fallback (docs/SECURITY.md): re-run the SAME
              // question against Claude, from scratch, below -- capped at
              // once per question by construction, since everything past
              // this point is the plain, non-fallback Claude path (if Claude
              // itself also fails, that's the existing honest-fallback/error
              // handling already in this file, not a further retry loop).
              // Logged with shape, not content, so real frequency is visible
              // in production without putting question text in logs.
              const lastMsg = conversation[conversation.length - 1];
              console.error("chat: kimi failed, falling back to claude", {
                reason: attempt.reason,
                questionChars: typeof lastMsg?.content === "string"
                  ? lastMsg.content.length
                  : JSON.stringify(lastMsg?.content ?? "").length,
                priorTurns: conversation.length,
              });
              usedFallback = true;
            }

            for (let i = 0; i < MAX_TOOL_ITERATIONS; i++) {
              const params: Anthropic.MessageStreamParams = {
                model: "claude-sonnet-5",
                // Sonnet 5 runs adaptive thinking even with no `thinking` param, and
                // budget_tokens (the old way to reserve thinking separately) is
                // REMOVED on this model -- so thinking and the answer text compete
                // for one shared max_tokens pool, with no way to partition it.
                //
                // `effort` is the lever that actually bounds thinking DEPTH, and it
                // is doing the real work here -- not max_tokens. Measured live
                // (throwaway operator, real data, this exact loop; 39 trials):
                //   - At the old 2048 with default effort, a two-vintage comparison
                //     spent the ENTIRE budget on thinking (2048/2048) and returned
                //     no text at all.
                //   - Raising max_tokens alone made it WORSE, not better: at 8000,
                //     thinking simply expanded to fill the new ceiling (7,999 and
                //     8,000 tokens observed), still returned blank on 2/11 trials,
                //     and pushed one model call to 67.6s. The heaviest question
                //     (5 vintages + a broad ask) failed 2/2 at 73.7s and 80.6s.
                //     Adaptive thinking has no fixed appetite to "leave room" for.
                //   - effort:"low" bounds it hard: peak thinking 0-400 tokens across
                //     8 trials spanning every question shape, 0/8 truncated, and
                //     two-vintage latency fell from 26-59s to 10.9-12.0s. The heavy
                //     probe passed 2/2 at 22.3-27.5s, peaking at 896 thinking
                //     tokens. Answer quality held: same three-part structure, same
                //     figures (both effort levels independently reported 2024's GDD
                //     ~27% above 2023's).
                // 4000 is ~1.85x the largest total output ever observed under this
                // config (2,156 tokens, heavy probe) -- real headroom without
                // re-inviting the runaway. Step to effort:"medium" (measured: adds
                // ~6-8s on two-vintage, still 0/6 truncated) if answers ever read as
                // too shallow. The honest-fallback below stays as the backstop.
                max_tokens: 4000,
                system: [{ type: "text", text: systemPrompt, cache_control: { type: "ephemeral" } }],
                tools: TOOLS,
                messages: withCacheBreakpoint([...conversation, ...newTurns]),
              };

              // `output_config.effort` postdates this project's pinned SDK types
              // (@anthropic-ai/sdk ^0.70, which is 0.70.1 -- the field lands in the
              // 0.124 types), but the API accepts and honors it today: verified by
              // direct measurement, with a clean dose-response across the three
              // levels (default -> 1,189-8,000 thinking tokens, medium -> 398-687,
              // low -> 0-400). Cast here rather than bumping the SDK 54 minor
              // versions under a live feature -- insights-scan shares the same pin.
              // If that pin is ever raised, delete the cast and move the field into
              // the typed object above.
              const modelStream = anthropic.messages.stream(
                { ...params, output_config: { effort: "low" } } as Anthropic.MessageStreamParams,
              );

              // finalMessage().usage DROPS output_tokens_details on this SDK
              // version -- confirmed directly: the raw message_delta event carries
              // {"output_tokens_details":{"thinking_tokens":33}} while
              // finalMessage() reports no such field at all. docs/SECURITY.md's
              // rule for this model says to verify thinking spend with exactly
              // that field, so it has to be captured off the raw event or the
              // check silently reports nothing forever.
              let thinkingTokens = 0;
              modelStream.on("streamEvent", (e) => {
                if (e.type === "message_delta") {
                  const t = (e.usage as { output_tokens_details?: { thinking_tokens?: number } } | undefined)
                    ?.output_tokens_details?.thinking_tokens;
                  if (typeof t === "number") thinkingTokens = t;
                }
              });
              // Text is forwarded from every turn, not only the terminal one. In
              // 39+ measured trials a tool_use turn emitted no text at all, so
              // this is near-theoretical -- but if one ever does, showing what
              // the model actually said beats the old behaviour of silently
              // discarding it.
              modelStream.on("text", (delta: string) => {
                if (delta) { sawText = true; send({ type: "text", text: delta }); }
              });

              const response = await modelStream.finalMessage();

              // Counts only, no content. Cache effectiveness is invisible from the
              // response body, and `cache_read_input_tokens` is the one field that
              // separates "the breakpoint below is working" from "we are silently
              // paying full price for the whole history on every turn" -- a
              // regression there is otherwise completely silent. Logged per model
              // turn so it is checkable in production, not only in a harness.
              const usage = response.usage;
              console.log("chat: usage " + JSON.stringify({
                turn: i,
                input: usage.input_tokens,
                cache_read: usage.cache_read_input_tokens ?? 0,
                cache_write: usage.cache_creation_input_tokens ?? 0,
                output: usage.output_tokens,
                thinking: thinkingTokens,
                stop: response.stop_reason,
              }));

              const content: Anthropic.ContentBlockParam[] = response.content;
              const stopReason: string | null = response.stop_reason;

              newTurns.push({ role: "assistant", content });

              const toolUses = content.filter(
                (b): b is Anthropic.ToolUseBlock => b.type === "tool_use",
              );

              // A max_tokens cutoff that still contains tool_use blocks behaves
              // like a normal tool_use turn, not a finished one: confirmed by
              // direct reproduction against the API that a cutoff lands at (or
              // just past) a tool_use block boundary, never mid-JSON -- the SDK
              // only ever hands back complete, parseable tool_use blocks, even
              // when one is missing a field the model didn't get to emit. Any
              // such gap is already caught by each tool's own input validation
              // in tools.ts (e.g. getSeries' bucket_hours check), which returns
              // a normal is_error tool_result rather than throwing -- so it's
              // safe to execute whatever calls did fit and loop for the rest,
              // instead of discarding tool calls the model already committed to
              // and silently returning nothing.
              if (stopReason === "tool_use" || (stopReason === "max_tokens" && toolUses.length)) {
                // Emitted only AFTER the model has committed to these calls, so
                // the status names work genuinely about to run rather than a
                // guess. Derived server-side rather than client-side on purpose:
                // tool arguments are model-controlled text, and building the
                // string here from whitelisted tokens only means no
                // model-authored string ever reaches the browser in this event.
                const status = describeToolCalls(toolUses);
                if (status) send({ type: "tool", text: status });

                const toolResults: Anthropic.ToolResultBlockParam[] = [];
                for (const block of toolUses) {
                  const result = await runTool(ctx.supabase, block.name, block.input as Record<string, unknown>);
                  toolResults.push({
                    type: "tool_result",
                    tool_use_id: block.id,
                    content: result.content,
                    is_error: result.isError,
                  });
                }
                newTurns.push({ role: "user", content: toolResults });
                continue;
              }

              // A genuinely terminal turn (no tool_use left to run) can still
              // carry no usable text -- most commonly a max_tokens cutoff that
              // landed entirely inside "thinking" before any text was written.
              // Surface that honestly instead of finishing with an empty bubble.
              if (!sawText) {
                console.error("chat: model turn produced no usable text", {
                  stop_reason: stopReason,
                  blockTypes: content.map((b) => b.type),
                });
                send({
                  type: "text",
                  text: stopReason === "max_tokens"
                    ? "That answer needed more room than I had to work with -- try narrowing the question (a specific block, vintage, or metric) and I'll try again."
                    : "I wasn't able to put together an answer for that -- try rephrasing the question.",
                });
              }

              // Fallback disclosure: appended after the answer is known (good
              // or honestly degraded), as its own small text event plus into
              // `newTurns` so it persists in the replayed conversation
              // history -- the operator should always see plainly that Kimi
              // failed and this reply came from the backup model, never find
              // out silently.
              if (usedFallback) {
                const note = "\n\n*(answered via backup model due to a processing issue)*";
                send({ type: "text", text: note });
                const last = newTurns[newTurns.length - 1];
                if (last.role === "assistant" && Array.isArray(last.content)) {
                  last.content = [...last.content, { type: "text", text: note }];
                }
              }

              // `truncated` rides on the done event rather than being concatenated
              // onto the reply the way it used to be: by this point the text has
              // already been streamed, so the note has to be appended client-side.
              send({
                type: "done",
                appended: newTurns,
                truncated: stopReason === "max_tokens",
              });
              return;
            }

            send({ type: "error", message: "conversation needed too many tool calls to resolve" });
          } catch (err) {
            console.error("chat: stream failed", err);
            send({ type: "error", message: "unexpected error" });
          } finally {
            controller.close();
          }
        },
      });

      return new Response(body, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
      });
    } catch (err) {
      console.error("chat: unexpected error", err);
      return Response.json({ error: "unexpected error" }, { status: 500 });
    }
  }),
};

// Every token below is either a hardcoded label or a value that passed a
// whitelist -- nothing the model wrote is ever interpolated into the status
// line. An unrecognised tool, metric, block or vintage degrades to the plain
// tool label (or is dropped entirely), never to a canned phrase describing work
// that isn't happening.
const TOOL_LABELS: Record<string, string> = {
  get_derived_series: "climate data",
  get_series: "sensor readings",
  get_anomalies: "anomaly checks",
  get_lot_analyses: "lab analyses",
  get_vessels: "tank inventory",
  get_labour_summary: "labour records",
};
const METRIC_LABELS: Record<string, string> = {
  air_temp: "air temperature",
  soil_moisture: "soil moisture",
  soil_temp: "soil temperature",
  humidity: "humidity",
  wind_speed: "wind speed",
  precip: "precipitation",
  solar: "solar radiation",
  uv: "UV",
  irrigation_volume: "irrigation volume",
};

function joinList(xs: string[]): string {
  if (xs.length <= 1) return xs[0] ?? "";
  return `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
}

function describeToolCalls(blocks: Anthropic.ToolUseBlock[]): string | null {
  // Grouped by tool so two get_derived_series calls read "climate data for 2022
  // and 2023" rather than repeating the phrase once per call.
  const groups = new Map<string, { vintages: Set<string>; scopes: Set<string>; metrics: Set<string> }>();
  for (const b of blocks) {
    const label = TOOL_LABELS[b.name];
    if (!label) continue;
    const input = (b.input ?? {}) as Record<string, unknown>;
    const g = groups.get(label) ?? { vintages: new Set(), scopes: new Set(), metrics: new Set() };

    const vintage = input.vintage;
    if (typeof vintage === "number" && Number.isInteger(vintage) && vintage >= 2000 && vintage <= 2100) {
      g.vintages.add(String(vintage));
    }
    const scope = input.block ?? input.block_id;
    if (typeof scope === "string" && /^B[1-9]$/.test(scope)) g.scopes.add(scope);
    const metric = input.metric;
    if (typeof metric === "string" && METRIC_LABELS[metric]) g.metrics.add(METRIC_LABELS[metric]);

    groups.set(label, g);
  }
  if (groups.size === 0) return null;

  const parts: string[] = [];
  for (const [label, g] of groups) {
    const head = g.metrics.size ? joinList([...g.metrics]) : label;
    const quals = [...g.scopes, ...g.vintages];
    parts.push(quals.length ? `${head} for ${joinList(quals)}` : head);
  }
  return `Reading ${joinList(parts)}`;
}

// A second cache breakpoint, on the GROWING END of the conversation, alongside
// the static one on the system block. The system breakpoint only ever covered
// tools+system -- measured at 3,417 tokens, about 1.3% of what a real
// conversation actually sends. Everything expensive is in `messages`: a single
// get_derived_series tool_result is 35KB+, and because this function is
// stateless the frontend replays the entire history on every question, so that
// payload was re-sent and re-billed at full price on every later model turn AND
// every later question.
//
// Measured over a real 4-turn conversation (throwaway operator, real data, this
// exact loop): full-price input tokens 258,970 -> 12, cache reads 17,085 ->
// 220,030, input-side cost down ~62% with cache writes counted at their 1.25x
// rate rather than netted out. This is a COST lever, not a speed one -- wall
// clock was indistinguishable, and the run that happened to be slower simply
// generated 37% more output tokens.
//
// Built as an immutable copy on purpose. `newTurns` is handed back to the
// frontend as `appended` and replayed verbatim on the next request, so
// annotating a block in place would send our own breakpoint back to us next
// turn; they would accumulate and eventually 400 against the API's limit of 4.
// Nothing here writes to `conversation` or `newTurns`.
//
// Note the string -> block conversion below is only a shape change, not a
// content change: the same user turn is sent as a bare string once it is no
// longer last, and the cached prefix still matches (confirmed live -- an 85
// token user message written to cache on one turn read back as part of a 3,502
// token hit on the next).
//
// TTL caveat: `ephemeral` means 5 minutes. A user who leaves the tab idle
// longer than that pays one fresh cache write on their next question and then
// reads normally again -- the intended trade, not a regression.
function withCacheBreakpoint(msgs: Anthropic.MessageParam[]): Anthropic.MessageParam[] {
  if (!msgs.length) return msgs;
  const cacheControl = { type: "ephemeral" as const };
  const out = msgs.slice();
  const last = out[out.length - 1];

  if (typeof last.content === "string") {
    out[out.length - 1] = {
      ...last,
      content: [{ type: "text", text: last.content, cache_control: cacheControl }],
    };
  } else if (Array.isArray(last.content) && last.content.length > 0) {
    const blocks = last.content.slice();
    const tail = blocks[blocks.length - 1];
    // Only block types that can actually carry a breakpoint. In this loop the
    // tail is always a tool_result (a tool turn) or a text block (the user
    // question, converted above) -- but `thinking`/`redacted_thinking` are in
    // the same union and cannot take cache_control, which tsc --strict
    // correctly rejects. Anything else is left unmarked: no breakpoint is
    // exactly the pre-change behaviour, so the fallback degrades to "no
    // saving" rather than to a 400.
    if (tail.type === "text" || tail.type === "tool_result") {
      blocks[blocks.length - 1] = { ...tail, cache_control: cacheControl };
      out[out.length - 1] = { ...last, content: blocks };
    }
  }
  return out;
}

function resolveDisplayName(role: string, firstName: string | null, lastName: string | null): string | null {
  if (!firstName) return null;
  return role === "operator" ? firstName : (lastName ? `${firstName} ${lastName}` : firstName);
}

function buildSystemPrompt(role: string, displayName: string | null): string {
  const shared = `You are a professional winemaker and viticulturist speaking on behalf of Mars Estate, a 7.35-acre Cabernet Sauvignon-dominant estate at roughly 2,200 ft on Howell Mountain, Napa Valley. You help estate operators and customers understand the vineyard and winery's real data -- climate, soil, irrigation, fermentation, lab chemistry, and harvest records -- by answering their questions using the tools available to you.

Always structure your answer in three parts, in this order:

1. Answer first. Open with a short, direct answer to what was asked and why it matters, in the voice described below for this user -- before the supporting detail.
2. The detail. Bring in the specific data and metrics that support your answer -- real numbers, dates, blocks, and vintages from the tools you called, not generalities. This is where technical precision belongs.
3. Takeaways. Close with what this means going forward -- a practical implication, a suggestion for what to look at next, or a natural follow-up question worth asking. Keep this brief and concrete to the actual finding, not a generic closer.

When discussing climate, soil, or farming metrics, connect them to what they plausibly mean for the resulting wine -- ripening pace, acid and tannin development, canopy stress, disease pressure, expected style -- not just the numbers themselves. For customers, this connection should be a substantial part of the answer, not an afterthought; they're asking about their wine, not a weather report. Always ground this in the specific data returned -- describe tendencies the conditions suggest, not a definitive claim about how the finished wine tastes, and never invent tasting notes not supportable by the data.

You only ever know what your tools return. If a tool returns no data for a question, say so plainly and suggest a nearby question that might have an answer, rather than guessing or filling the gap with something plausible-sounding. Never state a number, date, or finding that didn't come from a tool call.

- Never answer general knowledge questions unrelated to Mars Estate.
- Never use your own training knowledge to answer a question you could instead answer via a tool -- always call a tool first.
- When asked about likely wine characteristics, ground your answer in real climate/chemistry data via tools and general winemaking principles, but be clear you're describing likely tendencies based on growing conditions, not a definitive claim about the finished wine's taste. Never invent tasting notes not supportable by data.
- If asked something entirely unrelated to Mars Estate, politely decline and redirect to what you can help with.`;

  const nameNote = displayName
    ? ` The user's name is ${displayName}; address them by name naturally where it fits, not in every message.`
    : "";

  const toneBlock = role === "operator"
    ? `This user is an operator (team member).${nameNote} Be direct and technical. Lead with the data -- figures, comparisons, specific numbers -- before commentary; don't preface with pleasantries. Assume vineyard/winery domain fluency: don't explain what GDD or VPD are unless asked. Offer a proactive next step when relevant (e.g. "want me to compare this to last vintage?"), but keep it to one line.`
    : `This user is a customer (an Obsidian Member).${nameNote} Write the way a knowledgeable host at the estate would speak to a valued guest -- warm, genuine, and precise, never corporate or over-eager. Lead every answer with a short, plain-language explanation of what the data means for their wine or their block; don't open with a wall of numbers or a bulleted data dump. Mention specific figures in service of that explanation, and offer to go deeper ("I can pull the exact soil moisture readings if you'd like") rather than front-loading them. If a term needs it, gloss it briefly in the same sentence ("GDD -- the heat the vines have banked this season -- is running..."), not as a separate definition. Avoid generic luxury-marketing language (no "exquisite," "indulge," "unparalleled," "crafted") -- the tone should read as genuinely knowledgeable, not like ad copy. If something isn't available at their access level, say so warmly and redirect rather than stating it as a bare restriction (e.g. "That's something our team tracks internally -- happy to walk through your block's conditions or this vintage's story instead" rather than "That data is only available to operator accounts").`;

  const accessNote = `\n\nTools backed by RLS policies enforce access automatically -- get_lot_analyses, get_vessels, and get_labour_summary are operator-only and will return zero rows for a customer or pending user. Don't call an operator-only tool for a non-operator and then act surprised by the empty result -- you already know their role from this prompt.`;

  return `${shared}\n\n${toneBlock}${accessNote}`;
}
