import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";
import { createHandler } from "./handler.ts";

// Write-only ingestion of parsed ETS lab PDF reports, for a cloud scheduled
// task that must not hold a Supabase key (docs/ETS-INGEST.md). auth "none"
// here because the caller has no Supabase credential at all: handler.ts checks
// the dedicated x-ets-ingest-key against Vault before anything else runs.
export default {
  fetch: withSupabase({ auth: "none" }, (req, ctx) => createHandler(ctx)(req)),
};
