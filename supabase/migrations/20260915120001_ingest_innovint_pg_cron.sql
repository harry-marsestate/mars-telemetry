-- Schedules ingest-innovint (the new daily InnoVint sync Edge Function)
-- via pg_cron -> pg_net, matching ingest-climate-2026-daily's/
-- insights-scan's server-to-server pattern (auth:["secret"]).
--
-- IMPORTANT CAVEAT, stated plainly rather than silently papered over:
-- neither ingest-climate-2026-daily's nor insights-scan's actual
-- cron.schedule() call exists anywhere in this repo's migration history
-- (confirmed by grepping every migration for "cron."/"vault."/
-- "net.http_post" -- zero hits before this file). Both were set up live,
-- directly against the database, outside version control. This is
-- therefore NOT a copy of an existing committed pattern -- it is this
-- project's first committed cron.schedule(), built from the standard
-- Supabase pg_cron+pg_net+Vault idiom and from docs/SECURITY.md's own
-- "Two parallel API key systems" rule (an auth:["secret"] function needs
-- the NEW-format sb_secret_... key in its `apikey` header, never the
-- legacy service_role JWT). Whoever has access to the live database
-- should confirm this either matches or deliberately diverges from
-- ingest-climate-2026-daily/insights-scan's actual live definitions, and
-- ideally retrofit a migration recording those two as well so this gap
-- doesn't persist.
--
-- ONE-TIME MANUAL STEP REQUIRED BEFORE THIS SCHEDULE CAN SUCCEED (not
-- included in this migration -- a real secret value must never be
-- committed to a git-tracked file): run, once, against the live
-- database, with the project's actual sb_secret_... key (Project
-- Settings -> API Keys -> Secret keys):
--
--   select vault.create_secret(
--     '<the real sb_secret_... value>',
--     'ingest_innovint_auth_key',
--     'apikey header value for pg_cron -> ingest-innovint calls'
--   );
--
-- If a Vault secret already exists from setting up ingest-climate-2026-
-- daily/insights-scan, it would be cleaner to reuse that name here
-- instead of creating a second copy of the same key under a new name --
-- left as a follow-up for whoever reconciles the caveat above, since this
-- migration has no visibility into what (if anything) already exists in
-- Vault.
--
-- PLACEHOLDER SCHEDULE, not finalized: 07:00 UTC, chosen only as an
-- offset from ingest-climate-2026-daily's assumed early-morning slot
-- (itself unverified per the caveat above) so this doesn't obviously
-- collide. Must be checked against `select jobname, schedule from
-- cron.job` on the live database before this is treated as final --
-- attempting that read during the investigation for this feature was
-- blocked by this environment's own automated classifier ("Production
-- Reads"), so it was never actually confirmed collision-free.
select cron.schedule(
  'ingest-innovint-daily',
  '0 7 * * *',
  $$
  select net.http_post(
    url := 'https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/ingest-innovint',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'apikey', (
        select decrypted_secret from vault.decrypted_secrets
        where name = 'ingest_innovint_auth_key'
      )
    ),
    body := '{}'::jsonb,
    -- insights-engine's own history (docs/SECURITY.md: "fixed
    -- net.http_post's default 5s timeout, far under the function's real
    -- runtime") already found the pg_net default too short for a
    -- multi-phase Edge Function call. Set generously here up front
    -- rather than waiting to rediscover the same problem: this job's own
    -- timing investigation (see docs/SECURITY.md, "Daily InnoVint sync
    -- investigation") found the corrected 120-req/min-safe pacing alone
    -- implies a run well past 5s.
    timeout_milliseconds := 180000
  );
  $$
);
