import Anthropic from "@anthropic-ai/sdk";
import type { SupabaseClient } from "@supabase/server";

const SYSTEM_PROMPT = `You are a viticulture and enology analyst for Mars Estate, a 7.35-acre Cabernet-dominant estate at 1,600-1,750 ft on Howell Mountain, Napa Valley.

You will be given already-computed statistical findings as structured rows. Each row contains the two metrics, the measured effect size, the real sample size, the scope, and a confidence label. These numbers are final. Never recompute, re-rank, adjust, or introduce any figure not present in the row you were given. You have no access to underlying data and must not imply otherwise.

For each finding, do two things:

1. Judge whether it is worth surfacing. Reject it if the relationship is a restatement of a definition, a well-known meteorological identity, or has no plausible mechanism connecting the two quantities in a vineyard. Rejecting is the expected outcome for a meaningful share of findings -- say so plainly rather than manufacturing a rationale. A statistically strong finding with no credible mechanism is a false positive, not an insight.

2. If kept, write two to three sentences for one of these readers:
- A viticulturist, who cares what this changes about a decision they actually make: irrigation set timing and volume, canopy and leafing work, when to start berry sampling, which block to walk first in a heat event.
- A winemaker, who cares what it implies for fruit arriving at the crushpad and for cellar decisions: expected ripeness trajectory, acid retention, pick-window pressure, likely ferment behavior.
- A wine collector, who cares what makes a given vintage or block distinctive: how a season's conditions shaped a wine's character, why one block differs from another, what makes a bottling worth holding.

Ground every statement in the finding's own numbers. Name the block and vintage when the finding is scoped to them. Prefer the concrete over the general.

Never state a finding more confidently than its confidence label allows:
- reproduced: held in at least three of four seasons. You may describe it as a consistent pattern.
- single_season: observed in one season only. Say so explicitly, in the sentence itself.
- directional_only: fewer than six data points; there is no statistical confidence whatsoever. Describe only what the numbers show, always name the sample size in plain words, and never use "correlated," "significant," "predicts," "drives," or "because." Frame it as something to watch, not something established.

Never claim causation. Never invent tasting notes. Respond ONLY with a JSON array, one object per input row: {"id": <id>, "keep": true|false, "narration": "<text or empty if not keeping>"}.`;

interface Finding { id: number; [key: string]: unknown }
interface Verdict { id: number; keep: boolean; narration: string }

export async function narrateFindings(sb: SupabaseClient, findings: Finding[]) {
  const anthropic = new Anthropic({ apiKey: Deno.env.get("ANTHROPIC_API_KEY") });
  const model = "claude-sonnet-5";

  let raw: string;
  try {
    const response = await anthropic.messages.create({
      model, max_tokens: 2048,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: JSON.stringify(findings.map(stripToNarrationInput)) }],
    });
    raw = response.content.filter((b): b is Anthropic.TextBlock => b.type === "text").map(b => b.text).join("\n");
  } catch (err) {
    console.error("insights-scan/narrate: Anthropic call failed", err);
    return; // rows stay narrated_at:null, retried next run
  }

  const verdicts = parseVerdicts(raw);
  if (!verdicts) {
    console.error("insights-scan/narrate: could not parse response, leaving rows un-narrated. Raw response:", raw);
    return;
  }

  const now = new Date().toISOString();
  for (const v of verdicts) {
    const finding = findings.find(f => f.id === v.id);
    if (!finding) continue; // model referenced an id we didn't send -- ignore, don't guess
    if (v.keep) {
      await sb.from("insights").update({ narration: v.narration, narration_model: model, narrated_at: now })
        .eq("id", v.id);
    } else {
      await sb.from("insights").update({
        status: "below_threshold", rejection_reason: v.narration || "narration model vetoed: no plausible mechanism",
        narration_model: model, narrated_at: now,
      }).eq("id", v.id);
    }
  }
}

function stripToNarrationInput(f: Finding) {
  const { id, tier, metric_a, metric_b, effect, n_observations, lag_days, scope_kind, scope_block_id,
    scope_vintages, vintages_agreeing, vintages_tested, confidence_label } = f;
  return { id, tier, metric_a, metric_b, effect, n_observations, lag_days, scope_kind, scope_block_id,
    scope_vintages, vintages_agreeing, vintages_tested, confidence_label };
}

/** Defensive parsing: strip a markdown code fence if present, validate
 *  it's an array, validate every item has the required fields. Returns
 *  null on ANY failure -- the caller logs the raw text and leaves rows
 *  un-narrated rather than crashing or writing partial/malformed data. */
function parseVerdicts(raw: string): Verdict[] | null {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  const text = (fenced ? fenced[1] : raw).trim();
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return null; }
  if (!Array.isArray(parsed)) return null;
  const out: Verdict[] = [];
  for (const item of parsed) {
    if (typeof item !== "object" || item === null) return null;
    const { id, keep, narration } = item as Record<string, unknown>;
    if (typeof id !== "number" || typeof keep !== "boolean") return null;
    if (keep && typeof narration !== "string") return null;
    out.push({ id, keep, narration: typeof narration === "string" ? narration : "" });
  }
  return out;
}
