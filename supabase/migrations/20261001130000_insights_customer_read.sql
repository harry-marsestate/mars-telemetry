-- Customers get the vineyard "Insights and Anomalies" panel (docs/SECURITY.md,
-- "Insights and Anomalies for customers"). The Patterns half reads `insights`,
-- which was operator-only (insights_read). This adds a second, narrower
-- permissive read policy for customers; the operator policy is unchanged.
--
-- A customer may read an insight row only when ALL of these hold:
--   - status = 'surfaced' (what the panel shows; never rejected candidates);
--   - tab = 'vineyard' (winery insights stay operator-only);
--   - both metrics are customer-visible by the SAME rule sensor_read applies
--     to raw rows: metric_registry.min_role = 'all'. A derived metric
--     (gdd_day, dtr, vpd_kpa, vpd_peak_kpa, et0_in) is visible only if every
--     metric_derivation input of it is min_role 'all'. Anything in neither
--     table is NOT visible (default deny): harvest_yield_tons,
--     irrigation_volume (min_role 'operator'), and any labour or cost metric
--     a future scanner might add;
--   - its scope is estate-wide, or its block is one of accessible_blocks()
--     (customer_block_access), exactly like sensor_read's block gate.
--
-- Estate-scope rows: insights-scan builds estate series with
-- series_bucketed(p_block => null). For every vintage it scans (closed
-- vintages 2022-2025) the inputs of every customer-visible metric are
-- estate-wide rows (block_id is null, confirmed live 2026-10-01: 20,544 each
-- for air_temp/humidity/soil_moisture/soil_temp, zero per-block), which
-- sensor_read already shows to every approved customer whatever their blocks.
--
-- The helper is SECURITY DEFINER so a customer needs no grant on
-- metric_registry / metric_derivation; it reads only those two reference
-- tables and returns a boolean.

create or replace function public.customer_visible_metric(p_metric text)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from metric_registry where metric_key = p_metric and min_role = 'all')
      or (
        exists (select 1 from metric_derivation where metric_key = p_metric)
        and not exists (
          select 1 from metric_derivation d
          left join metric_registry r on r.metric_key = d.derived_from
          where d.metric_key = p_metric and coalesce(r.min_role, 'operator') <> 'all'
        )
      )
$$;
revoke all on function public.customer_visible_metric(text) from public, anon;
grant execute on function public.customer_visible_metric(text) to authenticated;

create policy insights_customer_read on public.insights for select using (
  (select current_role_name()) = 'customer'
  and status = 'surfaced'
  and tab = 'vineyard'
  and public.customer_visible_metric(metric_a)
  and public.customer_visible_metric(metric_b)
  and (scope_kind = 'estate' or scope_block_id in (select accessible_blocks()))
);
