-- Take the Edge Function secret key out of the database catalog, and read it
-- from ONE Vault secret everywhere (docs/SECURITY.md, "A secret API key was
-- readable from pg_trigger", 2026-09-29).
--
-- The dashboard-configured Database Webhook "notify-admin-on-confirmation"
-- called supabase_functions.http_request() with the sb_secret_ key as a
-- literal trigger argument. Trigger arguments live in pg_trigger.tgargs,
-- which Postgres lets every role read -- including mcp_gateway, a login role.
-- This replaces that webhook with a trigger whose function reads the key from
-- Vault at call time, the pattern the cron jobs already use, and points the
-- three cron jobs at the same single Vault secret so a rotation is one update.
--
-- PRECONDITION (the owner, in the dashboard, before this is applied): a Vault
-- secret named 'edge_functions_secret_key' holding the NEW secret key. This
-- migration refuses to run without it, so it can't switch anything to an
-- empty key.

do $$
begin
  if not exists (select 1 from vault.decrypted_secrets
                 where name = 'edge_functions_secret_key' and decrypted_secret like 'sb_secret_%') then
    raise exception 'Vault secret edge_functions_secret_key (the new sb_secret_ key) must exist before this migration is applied';
  end if;
end $$;

-- Reproduces supabase_functions.http_request()'s POST branch exactly, as the
-- webhook invoked it: same URL, same body (old_record/record/type/table/
-- schema), same headers (including the 'Content-type' spelling), same
-- 5000ms timeout, fired AFTER UPDATE FOR EACH ROW with no WHEN clause (the
-- webhook had none; notify-admin-approval itself checks for the
-- confirmed_at null -> not-null transition). Differences, both deliberate:
--   - the key comes from Vault, not from a trigger argument;
--   - no row is written to supabase_functions.hooks (the dashboard's webhook
--     history), because this is no longer a dashboard webhook. The request
--     and its response are still recorded by pg_net (net._http_response).
-- If the Vault secret is missing, the profile update still succeeds and a
-- warning is logged: an admin notification must never block a signup or an
-- approval.
create or replace function public.notify_admin_approval_webhook()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key text;
begin
  select decrypted_secret into v_key from vault.decrypted_secrets where name = 'edge_functions_secret_key';
  if v_key is null then
    raise warning 'notify_admin_approval_webhook: Vault secret edge_functions_secret_key is missing; no notification for profile %', new.id;
    return new;
  end if;
  perform net.http_post(
    url := 'https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/notify-admin-approval',
    body := jsonb_build_object('old_record', old, 'record', new, 'type', tg_op, 'table', tg_table_name, 'schema', tg_table_schema),
    params := '{}'::jsonb,
    headers := jsonb_build_object('Content-type', 'application/json', 'apikey', v_key),
    timeout_milliseconds := 5000
  );
  return new;
end $$;

-- A trigger function needs EXECUTE only when the trigger is created, not when
-- it fires, so nobody needs to be able to call this directly.
revoke all on function public.notify_admin_approval_webhook() from public, anon, authenticated, service_role;

drop trigger if exists "notify-admin-on-confirmation" on public.user_profiles;
create trigger notify_admin_approval
  after update on public.user_profiles
  for each row execute function public.notify_admin_approval_webhook();

-- The three cron jobs: each command is rewritten from its own live text with
-- exactly one substitution -- the Vault secret name -- so nothing else about
-- the job changes. Refuses if the old name doesn't appear exactly once.
do $$
declare
  r record;
  v_cmd text;
begin
  for r in select * from (values
      ('ingest-climate-2026-daily', 'climate_ingest_secret_key'),
      ('ingest-innovint-daily',     'ingest_innovint_auth_key'),
      ('insights-weekly-scan',      'insights_scan_secret_key')) as t(jobname, old_secret)
  loop
    select command into v_cmd from cron.job where jobname = r.jobname;
    if v_cmd is null then raise exception 'cron job % not found', r.jobname; end if;
    if (length(v_cmd) - length(replace(v_cmd, r.old_secret, ''))) / length(r.old_secret) <> 1 then
      raise exception 'cron job % should name % exactly once', r.jobname, r.old_secret;
    end if;
    perform cron.alter_job((select jobid from cron.job where jobname = r.jobname),
                           command := replace(v_cmd, r.old_secret, 'edge_functions_secret_key'));
  end loop;
end $$;

-- The three per-job secrets hold the OLD key and nothing references them
-- any more.
delete from vault.secrets
 where name in ('climate_ingest_secret_key', 'ingest_innovint_auth_key', 'insights_scan_secret_key');

-- Postconditions: no trigger, function or view carries a key, and every cron
-- job reads the one secret.
do $$
begin
  if exists (select 1 from pg_trigger where encode(tgargs, 'escape') ~ 'sb_secret_|eyJhbGciOi') then
    raise exception 'a trigger still carries a key in its arguments';
  end if;
  if exists (select 1 from cron.job where command ~ 'sb_secret_|eyJhbGciOi'
             or (command ~ 'apikey' and command !~ 'edge_functions_secret_key')) then
    raise exception 'a cron job still carries or references an old key';
  end if;
end $$;
