import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";
import Anthropic from "@anthropic-ai/sdk";
import { TOOLS, runTool } from "./tools.ts";

// RAG chat for Mars Estate/Mars Telemetry. ctx.supabase is RLS-scoped to the
// caller's own JWT for every tool call -- deliberately never ctx.supabaseAdmin,
// so a customer or pending user gets exactly the rows their role/RLS policies
// already allow (including zero rows), the same way the rest of the app works.
// Stateless: no conversation history persisted server-side -- the frontend
// sends the full message history every call and appends what we return.
export default {
  fetch: withSupabase({ auth: ["user"] }, async (req, ctx) => {
    try {
      const { messages } = await req.json();
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

      const anthropic = new Anthropic({ apiKey: Deno.env.get("ANTHROPIC_API_KEY") });

      const systemPrompt = buildSystemPrompt(role, displayName);
      const conversation: Anthropic.MessageParam[] = messages;
      const newTurns: Anthropic.MessageParam[] = [];

      // Bounds cost/latency on a single chat turn -- six round trips is far
      // more than any legitimate question over this tool set should need.
      const MAX_TOOL_ITERATIONS = 6;

      for (let i = 0; i < MAX_TOOL_ITERATIONS; i++) {
        const response = await anthropic.messages.create({
          model: "claude-sonnet-5",
          max_tokens: 2048,
          system: [{ type: "text", text: systemPrompt, cache_control: { type: "ephemeral" } }],
          tools: TOOLS,
          messages: [...conversation, ...newTurns],
        });

        newTurns.push({ role: "assistant", content: response.content });

        const hasToolUse = response.content.some((b) => b.type === "tool_use");

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
        if (response.stop_reason === "tool_use" || (response.stop_reason === "max_tokens" && hasToolUse)) {
          const toolResults: Anthropic.ToolResultBlockParam[] = [];
          for (const block of response.content) {
            if (block.type !== "tool_use") continue;
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

        const reply = response.content
          .filter((b): b is Anthropic.TextBlock => b.type === "text")
          .map((b) => b.text)
          .join("\n");

        // A genuinely terminal turn (no tool_use left to run) can still
        // carry no usable text -- most commonly a max_tokens cutoff that
        // landed entirely inside "thinking" before any text was written.
        // Surface that honestly instead of letting an empty string reach
        // the frontend, which silently renders as "(no response)" with
        // no indication anything went wrong.
        if (!reply.trim()) {
          console.error("chat: model turn produced no usable text", {
            stop_reason: response.stop_reason,
            blockTypes: response.content.map((b) => b.type),
          });
          const honest = response.stop_reason === "max_tokens"
            ? "That answer needed more room than I had to work with -- try narrowing the question (a specific block, vintage, or metric) and I'll try again."
            : "I wasn't able to put together an answer for that -- try rephrasing the question.";
          return Response.json({ reply: honest, appended: newTurns }, { status: 200 });
        }

        // Plain text, deliberately not wrapped in markdown emphasis -- the
        // frontend's renderer only supports **bold**, not *italics*, so a
        // single-asterisk wrap here would render as literal asterisks.
        const truncationNote = response.stop_reason === "max_tokens"
          ? "\n\n(Cut off before I could finish -- ask me to continue if you'd like the rest.)"
          : "";
        return Response.json({ reply: reply + truncationNote, appended: newTurns }, { status: 200 });
      }

      return Response.json(
        { error: "conversation needed too many tool calls to resolve" },
        { status: 500 },
      );
    } catch (err) {
      console.error("chat: unexpected error", err);
      return Response.json({ error: "unexpected error" }, { status: 500 });
    }
  }),
};

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
