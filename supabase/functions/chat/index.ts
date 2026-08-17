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
        .select("full_name")
        .maybeSingle();
      if (profileErr) console.error("chat: could not resolve caller profile", profileErr);
      const displayName = resolveDisplayName(role, profile?.full_name ?? null);

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

        if (response.stop_reason !== "tool_use") {
          const reply = response.content
            .filter((b): b is Anthropic.TextBlock => b.type === "text")
            .map((b) => b.text)
            .join("\n");
          return Response.json({ reply, appended: newTurns }, { status: 200 });
        }

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

function resolveDisplayName(role: string, fullName: string | null): string | null {
  if (!fullName || !fullName.trim()) return null;
  return role === "operator" ? fullName.trim().split(/\s+/)[0] : fullName.trim();
}

function buildSystemPrompt(role: string, displayName: string | null): string {
  const shared = `You are the Mars Telemetry assistant for Mars Estate, a vineyard and winery on Howell Mountain. You answer questions ONLY about Mars Estate's vineyard, winery, and operational data, using the tools provided.

- Never answer general knowledge questions unrelated to Mars Estate.
- Never use your own training knowledge to answer a question you could instead answer via a tool -- always call a tool first.
- If a tool returns no data (including due to the user's access level), say so honestly -- never fabricate a plausible-sounding number.
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
