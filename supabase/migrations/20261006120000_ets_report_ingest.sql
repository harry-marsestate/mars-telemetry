-- Write-only ingestion of parsed ETS lab PDF reports (docs/ETS-INGEST.md,
-- docs/SECURITY.md "ETS PDF report ingestion"). A cloud scheduled task POSTs
-- one parsed report sample at a time to the ingest-ets-report Edge Function
-- with a dedicated key; the function checks the key here and calls
-- ets_ingest_apply(), which validates and writes inside one transaction.
--
-- Same tables and conventions as the CSV path (ingestion/ets_labs): rows land
-- in lab_samples / lab_results / berry_volume_histogram, analysis_code is
-- analysis_code_for() from parse.py, block comes from parse.py's
-- DESCRIPTION_BLOCK (or an explicit block). Nothing about who can READ those
-- tables changes.
--
-- Scope: vineyard-side samples only (berry_maturity, berry_smoke). Their
-- vintage is the harvest-year rule applied to the sample date. Winery samples
-- carry the wine's vintage, which the rule cannot derive (docs/SECURITY.md,
-- "Vintage is the harvest year"), so winery analytes are quarantined as
-- unknown here and stay with the reviewed CSV path.
--
-- lab_samples gains NO columns: P1's database.checksum.winery_closed_vintages
-- hashes whole rows, so a new column would change every closed-vintage hash.
-- The report's own fields go in ets_report_samples instead.

-- ── collected_on_source: 'report' ──────────────────────────────────────
-- The PDF states the sample date, so it is neither embedded in the
-- description nor inferred from receipt.
alter table lab_samples drop constraint lab_samples_collected_on_source_check;
alter table lab_samples add constraint lab_samples_collected_on_source_check
  check (collected_on_source in ('description', 'inferred_from_receipt', 'report'));

-- ── Analyte spec: what this path accepts ───────────────────────────────
-- One row per analysis_code (as analysis_code_for() makes it). units: the
-- accepted spellings, first one canonical and stored; '' means unitless
-- (stored NULL, as the CSV path stores pH and the Dyostem bins). min/max:
-- plausibility bounds, deliberately wide -- a value outside them is a parse
-- error, not a bad vintage. dyostem_histogram is the 20 Dyostem bins
-- (value = berry count, written to berry_volume_histogram).
create table public.ets_analyte_spec (
  analysis_code text primary key,
  sample_type   text not null check (sample_type in ('berry_maturity', 'berry_smoke')),
  units         text[] not null check (cardinality(units) > 0),
  min_value     numeric not null,
  max_value     numeric not null check (max_value > min_value)
);
insert into public.ets_analyte_spec (analysis_code, sample_type, units, min_value, max_value) values
  -- the nine berry_maturity_by_block pivots on
  ('brix',                      'berry_maturity', '{degrees}',    0,    40),
  ('ph',                        'berry_maturity', '{""}',         2.5,  4.5),
  ('titratable_acidity',        'berry_maturity', '{g/L}',        1,    25),
  ('l_malic_acid',              'berry_maturity', '{g/L}',        0,    15),
  ('glucose_fructose',          'berry_maturity', '{g/L}',        0,    350),
  ('berry_weight',              'berry_maturity', '{g/berry}',    0.1,  5),
  ('berry_volume',              'berry_maturity', '{mL/berry}',   0.1,  5),
  ('berry_volume_variability',  'berry_maturity', '{%}',          0,    100),
  ('sugar_per_berry_by_volume', 'berry_maturity', '{mg/berry}',   0,    1000),
  ('dyostem_histogram',         'berry_maturity', '{""}',         0,    200),
  -- the nine free volatile phenols; berries in µg/kg, fruit in µg/L
  ('guaiacol',          'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('4_methylguaiacol',  'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('4_methylsyringol',  'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('m_cresol',          'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('o_cresol',          'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('p_cresol',          'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('cresols_sum',       'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('phenol',            'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  ('syringol',          'berry_smoke', '{µg/kg,µg/L}', 0, 1000),
  -- the six glycosylated conjugates
  ('smoke_glycosylated_markers_lcms_ms_qqq_guaiacol_rutinoside',          'berry_smoke', '{µg/kg,µg/L}', 0, 5000),
  ('smoke_glycosylated_markers_lcms_ms_qqq_4_methylguaiacol_rutinoside',  'berry_smoke', '{µg/kg,µg/L}', 0, 5000),
  ('smoke_glycosylated_markers_lcms_ms_qqq_4_methylsyringol_gentiobioside', 'berry_smoke', '{µg/kg,µg/L}', 0, 5000),
  ('smoke_glycosylated_markers_lcms_ms_qqq_cresol_rutinoside',            'berry_smoke', '{µg/kg,µg/L}', 0, 5000),
  ('smoke_glycosylated_markers_lcms_ms_qqq_phenol_rutinoside',            'berry_smoke', '{µg/kg,µg/L}', 0, 5000),
  ('smoke_glycosylated_markers_lcms_ms_qqq_syringol_gentiobioside',       'berry_smoke', '{µg/kg,µg/L}', 0, 5000);

-- ── Sample description -> block ────────────────────────────────────────
-- parse.py's DESCRIPTION_BLOCK, the berry entries (tests/ets-ingest-sql
-- checks they match). 'BUCKET FERMENT' (a trial_ferment, block unknown) is
-- deliberately absent: an unmapped description without an explicit block is
-- quarantined, never guessed.
create table public.ets_description_block (
  description text primary key,
  block_id    text not null references blocks(block_id)
);
insert into public.ets_description_block (description, block_id) values
  ('Mars Estate Blk: 2 (berries)', 'B2'), ('Mars Estate Blk: 3 (berries)', 'B3'),
  ('MRS 2 9/6/24', 'B2'),                 ('MRS 3 9/6/24', 'B3'),
  ('Mars, blk: 2 (berries)', 'B2'),       ('Mars, blk: 3 (berries)', 'B3'),
  ('MARS2', 'B2'),                        ('MARS3', 'B3'),
  ('Mars Blk 2 08/25/26 (berries)', 'B2'), ('Mars Blk 3 08/25/26 (berries)', 'B3'),
  ('Mars 2 (berries)', 'B2'),             ('Mars 3 (berries)', 'B3'),
  ('MARS 2 (berries)', 'B2'),             ('MARS 3 (berries)', 'B3');

-- ── Provenance of PDF-ingested samples ─────────────────────────────────
-- One row per lab_samples row this path wrote. Also how the path recognises
-- its own rows: a lab_sample_no without a row here came from the CSV path
-- and is never overwritten.
create table public.ets_report_samples (
  lab_sample_no     text primary key references lab_samples(lab_sample_no) on delete cascade,
  report_no         text not null,
  received_at       timestamptz not null,
  reported_at       timestamptz,
  source            text not null check (source = 'ets_pdf_email'),
  first_ingested_at timestamptz not null default now(),
  last_ingested_at  timestamptz not null default now()
);

-- ── Quarantine ─────────────────────────────────────────────────────────
-- One row per refused analyte, keyed like the write itself (report_no +
-- sample_id + analyte), so a re-sent report updates its rows instead of
-- piling up copies. A later successful write of the same key deletes the
-- row. Operators resolve the rest by fixing the parser or the spec and
-- re-sending, or by deleting the row (SQL editor).
create table public.ets_ingest_quarantine (
  id            bigint generated always as identity primary key,
  report_no     text not null,
  sample_id     text not null,
  analyte_name  text not null,
  sample_name   text,
  block         text,
  sample_date   text,
  analyte       jsonb not null,
  reason        text not null,
  source        text not null,
  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  seen_count    int not null default 1,
  unique (report_no, sample_id, analyte_name)
);

-- ── RLS ────────────────────────────────────────────────────────────────
-- Quarantine and provenance: operator read only, the same gate as
-- lab_samples. Spec and description map: no API access at all (read only by
-- the SECURITY DEFINER functions below). No API role can write any of them.
alter table public.ets_analyte_spec enable row level security;
alter table public.ets_description_block enable row level security;
alter table public.ets_report_samples enable row level security;
alter table public.ets_ingest_quarantine enable row level security;
revoke all on public.ets_analyte_spec, public.ets_description_block, public.ets_report_samples,
              public.ets_ingest_quarantine from public, anon, authenticated, service_role;
create policy ets_report_samples_read on public.ets_report_samples for select
  using (current_role_name() = 'operator');
grant select on public.ets_report_samples to authenticated;
create policy ets_ingest_quarantine_read on public.ets_ingest_quarantine for select
  using (current_role_name() = 'operator');
grant select on public.ets_ingest_quarantine to authenticated;

-- ── Run log ────────────────────────────────────────────────────────────
alter table system_health.ingestion_runs drop constraint ingestion_runs_asset_check;
alter table system_health.ingestion_runs add constraint ingestion_runs_asset_check
  check (asset in ('ingest-innovint', 'ingest-climate-2026', 'ingest-ets-report'));

-- ── analysis_code_for(), in SQL ────────────────────────────────────────
-- ingestion/ets_labs/parse.py: strip a " (GC/MS)" or " GC MS/MS" method
-- suffix, lower-case, µg -> ug, runs of anything but [a-z0-9] -> '_', trim
-- '_'. tests/ets-ingest-sql checks it against parse.py's output for every
-- analysis name in seed-data/lab_raw.
create function public.ets_analysis_code(p_name text)
returns text
language sql
immutable
set search_path = public
as $$
  with t as (select btrim(p_name, E' \t\r\n') as raw),
  b as (select case
                 when lower(raw) like '% (gc/ms)' then left(raw, length(raw) - 8)
                 when lower(raw) like '% gc ms/ms' then left(raw, length(raw) - 9)
                 else raw end as base from t)
  select btrim(regexp_replace(replace(lower(btrim(base, E' \t\r\n')), 'µg', 'ug'), '[^a-z0-9]+', '_', 'g'), '_') from b
$$;

-- ── Key check ──────────────────────────────────────────────────────────
-- The key lives in Vault as 'ets_ingest_key' (scripts/ets-ingest-key.mjs).
-- The Edge Function sends only its SHA-256; the key itself never reaches
-- Postgres or any log. A missing Vault secret means every request is refused.
create function public.ets_ingest_key_ok(p_key_sha256 text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(p_key_sha256 ~ '^[0-9a-f]{64}$', false) and exists (
    select 1 from vault.decrypted_secrets
     where name = 'ets_ingest_key'
       and encode(sha256(convert_to(decrypted_secret, 'UTF8')), 'hex') = p_key_sha256)
$$;

-- ── The write ──────────────────────────────────────────────────────────
-- Returns {ok, http_status, ...}. ok=false (400) only for a payload that is
-- malformed as a whole; content problems are quarantined per analyte and
-- reported per row. One transaction: either the whole valid part of the
-- sample is written, or (on an unexpected error) nothing is.
create function public.ets_ingest_apply(p_key_sha256 text, p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  c_date_re constant text := '^\d{4}-\d{2}-\d{2}$';
  c_ts_re   constant text := '^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?$';
  c_tz_re   constant text := '^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}(:?\d{2})?)$';
  v_report text; v_sample text; v_name text; v_block_in text; v_source text;
  v_sample_date date; v_received timestamptz; v_reported timestamptz;
  v_analytes jsonb; v_a jsonb; v_i int;
  v_block text; v_mapped text; v_has_map boolean; v_vintage int;
  v_sample_reason text; v_existing record; v_own record;
  v_types text[]; v_type text;
  v_rows jsonb := '[]'::jsonb; v_valid jsonb := '[]'::jsonb;
  v_aname text; v_code text; v_spec record; v_unit text; v_raw text; v_m text[];
  v_op text; v_num numeric; v_at timestamptz; v_bin numeric; v_reason text;
  v_seen text[] := '{}';
  v_sample_pk bigint; v_rid bigint; v_action text;
  v_written int := 0; v_quarantined int := 0;
begin
  if not public.ets_ingest_key_ok(p_key_sha256) then
    return jsonb_build_object('ok', false, 'http_status', 401, 'reason', 'invalid key');
  end if;

  -- ── shape: a malformed report is refused whole (400), nothing written ──
  if jsonb_typeof(p_payload) is distinct from 'object' then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'payload must be a JSON object');
  end if;
  v_source := p_payload->>'source';
  v_report := btrim(p_payload->>'report_no');
  v_sample := btrim(p_payload->>'sample_id');
  v_name := btrim(p_payload->>'sample_name');
  v_block_in := nullif(btrim(p_payload->>'block'), '');
  v_analytes := p_payload->'analytes';
  if v_source is distinct from 'ets_pdf_email' then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'source must be "ets_pdf_email"');
  elsif coalesce(v_report, '') !~ '^[A-Za-z0-9._/-]{1,64}$' then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'report_no is required (1-64 of A-Z a-z 0-9 . _ / -)');
  elsif coalesce(v_sample, '') !~ '^[A-Za-z0-9-]{1,32}$' then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'sample_id is required (1-32 of A-Z a-z 0-9 -)');
  elsif coalesce(v_name, '') = '' or length(v_name) > 200 then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'sample_name is required (at most 200 characters)');
  elsif coalesce(p_payload->>'sample_date', '') !~ c_date_re then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'sample_date must be YYYY-MM-DD');
  elsif coalesce(p_payload->>'received_at', '') !~ c_date_re and coalesce(p_payload->>'received_at', '') !~ c_tz_re then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'received_at must be YYYY-MM-DD or an ISO 8601 timestamp with an offset');
  elsif p_payload ? 'reported_at' and jsonb_typeof(p_payload->'reported_at') <> 'null'
        and coalesce(p_payload->>'reported_at', '') !~ c_date_re and coalesce(p_payload->>'reported_at', '') !~ c_tz_re then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'reported_at must be null, YYYY-MM-DD or an ISO 8601 timestamp with an offset');
  elsif jsonb_typeof(v_analytes) is distinct from 'array' or jsonb_array_length(v_analytes) = 0 or jsonb_array_length(v_analytes) > 200 then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'analytes must be an array of 1-200 objects');
  end if;
  for v_i in 0 .. jsonb_array_length(v_analytes) - 1 loop
    v_a := v_analytes->v_i;
    if jsonb_typeof(v_a) is distinct from 'object' or coalesce(btrim(v_a->>'name'), '') = '' or length(v_a->>'name') > 200 then
      return jsonb_build_object('ok', false, 'http_status', 400, 'reason', format('analytes[%s] must be an object with a name (at most 200 characters)', v_i));
    end if;
    if btrim(v_a->>'name') = any (v_seen) then
      return jsonb_build_object('ok', false, 'http_status', 400, 'reason', format('analytes[%s]: duplicate analyte name %s', v_i, btrim(v_a->>'name')));
    end if;
    v_seen := v_seen || btrim(v_a->>'name');
  end loop;
  begin
    v_sample_date := (p_payload->>'sample_date')::date;
    -- A date alone is that day's Pacific midnight.
    v_received := case when p_payload->>'received_at' ~ c_date_re
                       then ((p_payload->>'received_at')::date)::timestamp at time zone 'America/Los_Angeles'
                       else (p_payload->>'received_at')::timestamptz end;
    v_reported := case when p_payload->>'reported_at' is null then null
                       when p_payload->>'reported_at' ~ c_date_re
                       then ((p_payload->>'reported_at')::date)::timestamp at time zone 'America/Los_Angeles'
                       else (p_payload->>'reported_at')::timestamptz end;
  exception when others then
    return jsonb_build_object('ok', false, 'http_status', 400, 'reason', 'sample_date, received_at or reported_at is not a real date: ' || sqlerrm);
  end;

  -- One writer per sample at a time (concurrent re-sends of one report).
  perform pg_advisory_xact_lock(hashtextextended('ets_ingest:' || v_sample, 0));

  -- ── sample-level checks: any failure quarantines every analyte ──
  -- Block: explicit 'B2' / '2' / 'Block 2' style, or the description map.
  select block_id into v_mapped from ets_description_block where description = v_name;
  v_has_map := found;
  if v_block_in is not null then
    v_m := regexp_match(v_block_in, '^(?:b|blk|block)?[\s:.#-]*(\d{1,2})$', 'i');
    v_block := case when v_m is null then v_block_in else 'B' || (v_m[1])::int end;
  else
    v_block := v_mapped;
  end if;

  if v_sample ~ '^\d{9}[A-Za-z]$' then
    v_sample_reason := 'lettered sample number: possibly a reissue of ' || left(v_sample, 9) || ', needs an operator decision (the CSV path checks each one by hand)';
  elsif v_sample !~ '^\d{9}$' then
    v_sample_reason := 'sample_id is not a 9-digit ETS sample number';
  elsif v_block is null then
    v_sample_reason := 'block unknown: no block given and sample_name is not in ets_description_block';
  elsif not exists (select 1 from blocks where block_id = v_block) then
    v_sample_reason := format('block %s is not a known block', v_block_in);
  elsif v_has_map and v_block_in is not null and v_mapped <> v_block then
    v_sample_reason := format('block %s disagrees with sample_name %s, which maps to %s', v_block_in, v_name, v_mapped);
  end if;

  if v_sample_reason is null then
    -- Harvest-year rule on the sample date (Pacific noon, so the date alone decides).
    v_vintage := public.harvest_vintage((v_sample_date + time '12:00') at time zone 'America/Los_Angeles');
    if not exists (select 1 from vintages where vintage = v_vintage) then
      v_sample_reason := format('vintage %s (harvest-year rule on %s) is not in public.vintages', v_vintage, v_sample_date);
    end if;
  end if;

  if v_sample_reason is null then
    select s.id, s.sample_type, s.source_file into v_existing from lab_samples s where s.lab_sample_no = v_sample;
    if found then
      select * into v_own from ets_report_samples where lab_sample_no = v_sample;
      if not found then
        v_sample_reason := format('sample %s already exists from %s (CSV path); not overwritten', v_sample, v_existing.source_file);
      elsif v_own.report_no <> v_report then
        v_sample_reason := format('sample %s already belongs to report %s', v_sample, v_own.report_no);
      end if;
    end if;
  end if;

  -- Sample type from the known analytes; a mix of maturity and smoke is refused.
  if v_sample_reason is null then
    select array_agg(distinct s.sample_type) into v_types
      from jsonb_array_elements(v_analytes) a
      join ets_analyte_spec s on s.analysis_code =
        case when a->>'name' ~* '^\s*Dyostem Histogram\s*:' then 'dyostem_histogram' else public.ets_analysis_code(a->>'name') end;
    if cardinality(v_types) > 1 then
      v_sample_reason := 'analytes mix berry maturity and smoke markers in one sample';
    elsif v_types is not null then
      v_type := v_types[1];
      if v_existing.id is not null and v_existing.sample_type <> v_type then
        v_sample_reason := format('sample %s was written as %s; these analytes are %s', v_sample, v_existing.sample_type, v_type);
      end if;
    end if;
  end if;

  -- ── per analyte ──
  for v_i in 0 .. jsonb_array_length(v_analytes) - 1 loop
    v_a := v_analytes->v_i;
    v_aname := btrim(v_a->>'name');
    v_reason := v_sample_reason;
    v_code := null; v_bin := null; v_op := null; v_num := null; v_at := null; v_raw := null; v_unit := null;

    if v_reason is null then
      v_m := regexp_match(v_aname, '^Dyostem Histogram\s*:\s*([0-9]+(?:\.[0-9]+)?)$', 'i');
      if v_m is not null then
        v_code := 'dyostem_histogram';
        v_bin := v_m[1]::numeric;
        if v_bin not in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0) then
          v_reason := format('Dyostem bin %s is not one of 0.1-2.0 mL', v_m[1]);
        end if;
      else
        v_code := public.ets_analysis_code(v_aname);
      end if;
    end if;

    if v_reason is null then
      select * into v_spec from ets_analyte_spec where analysis_code = v_code;
      if not found then
        v_reason := format('unknown analyte (analysis_code %s): not in ets_analyte_spec', v_code);
      end if;
    end if;

    if v_reason is null then
      -- Unit: µ (micro sign) and μ (Greek mu) and a leading "ug" are one spelling.
      v_unit := coalesce(btrim(v_a->>'unit'), '');
      v_unit := regexp_replace(replace(v_unit, 'μ', 'µ'), '^ug', 'µg');
      if not (v_unit = any (v_spec.units)) then
        v_reason := format('unit %s is not accepted for %s (expected %s)',
          coalesce(nullif(v_a->>'unit', ''), '(none)'), v_code,
          array_to_string(array(select coalesce(nullif(u, ''), '(none)') from unnest(v_spec.units) u), ' or '));
      end if;
    end if;

    if v_reason is null then
      -- Value: a number, or a string "n" / "< n" (detection-limit censored).
      if jsonb_typeof(v_a->'value') = 'number' then
        v_raw := v_a->>'value';
      elsif jsonb_typeof(v_a->'value') = 'string' then
        v_raw := btrim(v_a->>'value');
      end if;
      v_m := regexp_match(coalesce(v_raw, ''), '^\s*(<)?\s*([+-]?\d+(?:\.\d+)?)\s*$');
      if v_m is null then
        v_reason := format('value %s is not a number or "< number"', coalesce(v_a->>'value', 'null'));
      else
        v_op := case when v_m[1] is null then '=' else '<' end;
        v_num := v_m[2]::numeric;
        if v_num < v_spec.min_value or v_num > v_spec.max_value then
          v_reason := format('value %s is outside %s..%s for %s', v_num, v_spec.min_value, v_spec.max_value, v_code);
        elsif v_code = 'dyostem_histogram' and (v_op <> '=' or v_num <> trunc(v_num)) then
          v_reason := 'a Dyostem bin count must be a whole number';
        end if;
      end if;
    end if;

    if v_reason is null then
      -- analyzed_at: the wall-clock ETS prints, stored as UTC -- the same
      -- convention the CSV path produces (docs/ETS-INGEST.md, "Timestamps").
      if coalesce(v_a->>'analysis_date', '') !~ c_ts_re then
        v_reason := 'analysis_date must be YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS], without an offset';
      else
        begin
          v_at := (v_a->>'analysis_date')::timestamp at time zone 'UTC';
        exception when others then
          v_reason := 'analysis_date is not a real date';
        end;
      end if;
    end if;

    if v_reason is null then
      v_valid := v_valid || jsonb_build_object('i', v_i, 'name', v_aname, 'code', v_code, 'bin', v_bin, 'op', v_op,
        'num', v_num, 'raw', v_raw, 'unit', nullif(v_spec.units[1], ''), 'at', v_at);
      v_rows := v_rows || jsonb_build_object('analyte', v_aname, 'status', 'pending');
    else
      insert into ets_ingest_quarantine as q (report_no, sample_id, analyte_name, sample_name, block, sample_date, analyte, reason, source)
      values (v_report, v_sample, v_aname, v_name, v_block_in, p_payload->>'sample_date', v_a, v_reason, v_source)
      on conflict (report_no, sample_id, analyte_name) do update set
        sample_name = excluded.sample_name, block = excluded.block, sample_date = excluded.sample_date,
        analyte = excluded.analyte, reason = excluded.reason, last_seen_at = now(), seen_count = q.seen_count + 1;
      v_quarantined := v_quarantined + 1;
      v_rows := v_rows || jsonb_build_object('analyte', v_aname, 'status', 'quarantined', 'reason', v_reason);
    end if;
  end loop;

  -- ── write the valid part ──
  if jsonb_array_length(v_valid) > 0 then
    insert into lab_samples as s (lab_sample_no, lab_group_no, sample_description_raw, sample_type, block_id, vintage,
                                  collected_on, collected_on_source, received_on, reissue_of, fruit_source, source_system, source_file)
    values (v_sample, v_report, v_name, v_type, v_block, v_vintage, v_sample_date, 'report',
            (v_received at time zone 'America/Los_Angeles')::date, null, 'estate', 'ets_labs', 'ets_pdf_email')
    on conflict (lab_sample_no) do update set
      lab_group_no = excluded.lab_group_no, sample_description_raw = excluded.sample_description_raw,
      sample_type = excluded.sample_type, block_id = excluded.block_id, vintage = excluded.vintage,
      collected_on = excluded.collected_on, collected_on_source = excluded.collected_on_source,
      received_on = excluded.received_on
    returning id into v_sample_pk;

    insert into ets_report_samples as r (lab_sample_no, report_no, received_at, reported_at, source)
    values (v_sample, v_report, v_received, v_reported, v_source)
    on conflict (lab_sample_no) do update set
      received_at = excluded.received_at, reported_at = excluded.reported_at, last_ingested_at = now();

    for v_a in select * from jsonb_array_elements(v_valid) loop
      if v_a->>'code' = 'dyostem_histogram' then
        insert into berry_volume_histogram as h (sample_id, bin_ml, berry_count, analyzed_at)
        values (v_sample_pk, (v_a->>'bin')::numeric, (v_a->>'num')::numeric::int, (v_a->>'at')::timestamptz)
        on conflict (sample_id, bin_ml) do update set berry_count = excluded.berry_count, analyzed_at = excluded.analyzed_at
        returning case when xmax = 0 then 'inserted' else 'updated' end into v_action;
      else
        -- Keyed on (sample, analyte name): a re-send with a corrected
        -- analysis_date updates the row instead of adding a second one.
        update lab_results set
          analysis_code = v_a->>'code', result_raw = v_a->>'raw', result_numeric = (v_a->>'num')::numeric,
          result_operator = v_a->>'op', units = v_a->>'unit', analyzed_at = (v_a->>'at')::timestamptz
        where sample_id = v_sample_pk and analysis_name_raw = v_a->>'name'
        returning id into v_rid;
        if found then
          v_action := 'updated';
        else
          insert into lab_results (sample_id, analysis_name_raw, analysis_code, result_raw, result_numeric, result_operator, units, analyzed_at)
          values (v_sample_pk, v_a->>'name', v_a->>'code', v_a->>'raw', (v_a->>'num')::numeric, v_a->>'op', v_a->>'unit', (v_a->>'at')::timestamptz);
          v_action := 'inserted';
        end if;
      end if;
      delete from ets_ingest_quarantine where report_no = v_report and sample_id = v_sample and analyte_name = v_a->>'name';
      v_written := v_written + 1;
      v_rows := jsonb_set(v_rows, array[(v_a->>'i')], jsonb_build_object('analyte', v_a->>'name', 'status', 'written',
        'analysis_code', v_a->>'code', 'target', case when v_a->>'code' = 'dyostem_histogram' then 'berry_volume_histogram' else 'lab_results' end,
        'action', v_action));
    end loop;
  end if;

  return jsonb_build_object(
    'ok', true,
    'http_status', case when v_quarantined = 0 then 200 else 207 end,
    'report_no', v_report,
    'sample_id', v_sample,
    'sample', case
      when v_sample_reason is not null then jsonb_build_object('status', 'quarantined', 'reason', v_sample_reason)
      when v_written = 0 then jsonb_build_object('status', 'not_written', 'reason', 'no analyte passed validation')
      else jsonb_build_object('status', 'written', 'lab_sample_no', v_sample, 'block_id', v_block, 'vintage', v_vintage, 'sample_type', v_type) end,
    'written', v_written,
    'quarantined', v_quarantined,
    'rows', v_rows);
end $$;

revoke all on function public.ets_analysis_code(text) from public, anon, authenticated;
revoke all on function public.ets_ingest_key_ok(text) from public, anon, authenticated;
revoke all on function public.ets_ingest_apply(text, jsonb) from public, anon, authenticated;
grant execute on function public.ets_ingest_key_ok(text) to service_role;
grant execute on function public.ets_ingest_apply(text, jsonb) to service_role;
-- log_ingestion_run (service_role, unchanged) records each run.
