-- P2: health-probe at 12:10 UTC nightly (docs/SECURITY.md, "Nightly health
-- checks"). Same call shape as the ingest jobs: the key is read from Vault by
-- name at call time, never embedded. Six sequential probes normally finish in
-- ~2s; the worst case (every probe timing out twice) is ~200s, hence 180s.
select cron.schedule('health-p2-probes', '10 12 * * *', $cmd$
  select net.http_post(
    url := 'https://wwdpunaefaiazsjamrkc.supabase.co/functions/v1/health-probe',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'apikey', (
        select decrypted_secret from vault.decrypted_secrets
        where name = 'edge_functions_secret_key'
      )
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 180000
  );
$cmd$);
