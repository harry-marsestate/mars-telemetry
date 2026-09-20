-- harvest_receipts contains one 2026 row (innovint_receipt_id
-- grwrec_23EDRM094PK23IDDN21MQ89P, varietal_name='Syrah', 1.918 tons,
-- block_id NULL) that the owner has confirmed is not Mars Estate's --
-- Mars has never grown or vinified Syrah, and this project's own
-- reconciliation (docs/SECURITY.md) already established no Syrah block
-- or lot exists anywhere. The working theory (owner-directed, not
-- investigated further here) is a cross-tenant artifact on InnoVint's
-- side. Confirmed live before this migration: it is the ONLY 2026 row
-- in harvest_receipts, and because domain_reality()'s harvest_receipts
-- clause is existence-based (`exists(... where vintage=v)`), this one
-- foreign row alone currently makes 2026 harvest report as REAL to the
-- dashboard and chat -- real receipts actually stop at 2024 (B2/B3 Cab).
--
-- Deleting it is not a fix: ingest-innovint upserts on
-- (source_system, source_id) daily, so a deleted row returns on the
-- next sync. Same shape of problem block_innovint_map and
-- lot_canonical_map already solve for other upstream-identity
-- questions -- an explicit, auditable record of what's excluded and
-- why, not a hardcoded predicate buried in a view. The raw synced row
-- is never touched: this is a read-side exclusion, not a data
-- deletion -- we don't destroy real upstream data, even data that
-- isn't ours.
create table harvest_receipts_excluded (
  innovint_receipt_id text primary key references harvest_receipts(innovint_receipt_id),
  reason               text not null,
  confidence           text not null check (confidence in ('confirmed', 'provisional')),
  excluded_at          timestamptz not null default now()
);

-- Same open-read shape as harvest_receipts itself (confirmed live:
-- harvest_receipts grants SELECT to authenticated with a `using (true)`
-- policy, visible to customers as well as operators) -- this table is
-- exclusion metadata about that same data, not a new sensitivity tier.
alter table harvest_receipts_excluded enable row level security;
grant select on harvest_receipts_excluded to authenticated;
create policy harvest_receipts_excluded_read on harvest_receipts_excluded
  for select using (true);

insert into harvest_receipts_excluded (innovint_receipt_id, reason, confidence) values
  ('grwrec_23EDRM094PK23IDDN21MQ89P',
   'Syrah, 1.918 tons, 2026-09-11, block_id NULL. Mars Estate has never '
   'grown or vinified Syrah (owner-confirmed) -- no Syrah block, no '
   'Syrah lot anywhere in lot_analyses/vessels, block_id null on this '
   'row itself. Working theory: a cross-tenant artifact reaching this '
   'InnoVint account from another winery. This is the ONLY 2026 '
   'harvest_receipts row -- excluding it correctly returns 2026 harvest '
   'to "no real receipts yet" rather than the single foreign row making '
   'the whole vintage report as real. Owner-directed: investigate no '
   'further, exclude and move on.',
   'confirmed');

-- harvest_receipts_current: the read surface every consumer should use
-- from here on, same naming convention as lab_samples_current/
-- lab_results_current/berry_volume_histogram_current -- exclude, don't
-- destroy. security_invoker so a caller who can't read
-- harvest_receipts/harvest_receipts_excluded directly gets nothing from
-- the view either.
create view harvest_receipts_current as
select h.*
from harvest_receipts h
where not exists (
  select 1 from harvest_receipts_excluded e where e.innovint_receipt_id = h.innovint_receipt_id
);

alter view harvest_receipts_current set (security_invoker = true);
grant select on harvest_receipts_current to authenticated;

-- domain_reality()'s Tier-3 harvest_receipts clause now reads
-- harvest_receipts_current -- full function body copied forward from
-- the current live definition (confirmed via pg_get_functiondef before
-- writing this) with that one clause changed, same pattern every prior
-- domain_reality() migration in this project has used.
create or replace function domain_reality(p_vintages int[])
returns table(domain text, vintage int, is_real boolean)
language plpgsql stable security definer
set search_path = public as $$
declare
  sensor_domains text[] := array['air_temp','humidity','precipitation','soil_moisture','soil_temp',
                                  'irrigation_volume','wind_speed','wind_dir','uv',
                                  'cellar_temp','cellar_rh','ferment_temp','ferment_brix'];
begin
  return query
    select c.metric_key, c.vintage, true
    from real_metric_vintage_counts(sensor_domains, p_vintages) c
  union all
    select d, v, false
    from unnest(sensor_domains) d, unnest(p_vintages) v
    where not exists (
      select 1 from real_metric_vintage_counts(sensor_domains, p_vintages) c
      where c.metric_key = d and c.vintage = v
    )
  union all
    select bridge.domain, v.vintage, bool_and(coalesce(t1.is_real, false))
    from (values
      ('gdd_cumulative_calibrated','gdd_day'),
      ('dtr_f','dtr'),
      ('vpd_kpa','vpd_kpa'),
      ('vpd_peak_kpa','vpd_peak_kpa'),
      ('et0_in','et0_in')
    ) as bridge(domain, derivation_key)
    cross join unnest(p_vintages) as v(vintage)
    join metric_derivation md on md.metric_key = bridge.derivation_key
    left join (
      select c.metric_key, c.vintage, true as is_real
      from real_metric_vintage_counts(sensor_domains, p_vintages) c
    ) t1 on t1.metric_key = md.derived_from and t1.vintage = v.vintage
    group by bridge.domain, v.vintage
  union all
    -- Changed: harvest_receipts_current, not harvest_receipts directly
    -- -- excludes the Syrah cross-tenant row (and any future exclusion)
    -- from the existence check, so a foreign row can never again make a
    -- vintage report as real on its own.
    select 'harvest_receipts', v.vintage,
      exists(select 1 from harvest_receipts_current h where h.vintage = v.vintage and h.source_system = 'innovint')
    from unnest(p_vintages) as v(vintage)
  union all
    select 'labour', v.vintage,
      exists(select 1 from labour_actuals la where la.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    select 'berry_sampling', v.vintage,
      exists(select 1 from lab_samples ls where ls.vintage = v.vintage)
    from unnest(p_vintages) as v(vintage)
  union all
    select dom, v.vintage, real_flag
    from unnest(p_vintages) as v(vintage),
         (values ('lot_analyses', true), ('vessels', true), ('solar', false)) as f(dom, real_flag);
end;
$$;
