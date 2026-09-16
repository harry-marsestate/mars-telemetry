-- Real labour data: replaces the 100%-simulated work_events/labour_summary
-- pipeline (see the companion drop migration) with actual Silverado hours
-- invoices (2023, 2024) and the Mars Invoice Backup (labor + expenses,
-- July 2026). See docs/SECURITY.md's real-labour-ingestion entry for the
-- full source/checksum writeup.
--
-- Schema note (deviation from the originally proposed field list, stated
-- per that proposal's own "adjust if you find a better fit" allowance):
-- added source_row_id. Labour line items have no natural business key --
-- two crew members can log identical job_category/task/role/hours/rate on
-- the same invoice (confirmed: several such pairs exist in the real 2024
-- data), so unlike sensor_readings (metric_key+sensor_id+recorded_at) or
-- irrigation (date+block_id), there is nothing to upsert on that wouldn't
-- silently collapse two genuinely distinct rows into one. source_row_id is
-- the row's position in its source sheet (stable across re-runs of the
-- same file) -- paired with source_file it gives every row a real,
-- idempotent identity without inventing one that could mask a duplicate.
create table labour_actuals (
  id             bigint generated always as identity primary key,
  vintage        int not null references vintages(vintage),
  period_month   date not null,                 -- 1st of the month
  invoice_number text,
  -- Farming/Development (2024 Raw Data) or Mars Farming/Mars Development
  -- (Mars Invoice Backup, both tabs) -- null for 2023, which predates the
  -- Farming/Development split entirely.
  invoice_type   text,
  job_category   text not null,
  task           text,                          -- code prefix stripped, e.g. 'Tuck Shoots & Wire movement'
  task_code      text,                           -- e.g. '028'
  role           text,                           -- code prefix stripped, e.g. 'General Labor'
  role_code      text,                           -- e.g. '028.00'
  hours          numeric,                        -- null for entry_kind='expense'
  rate_per_hour  numeric,                        -- null for entry_kind='expense'
  amount_usd     numeric not null,
  entry_kind     text not null check (entry_kind in ('labor','expense')),
  check (entry_kind <> 'expense' or hours is null),
  -- Expense-only fields (Mars Invoice Backup 'Expenses' tab). job_category
  -- above already holds the FOLDED category (account name mapped:
  -- 'Fertilize'/'Disease Control'/'Irrigation'/'Other' -- see
  -- docs/SECURITY.md) so aggregate queries never need to branch on
  -- entry_kind to group correctly; expense_account keeps the original
  -- numbered account string for traceability back to the source.
  expense_vendor text,
  expense_memo   text,
  expense_account text,
  expense_date   date,
  source_system  text not null,
  source_file    text not null,
  source_row_id  int not null,
  ingested_at    timestamptz default now(),
  unique (source_file, source_row_id)
);
create index on labour_actuals (vintage, job_category);
create index on labour_actuals (vintage, entry_kind);

alter table labour_actuals enable row level security;

-- Same access shape as the work_events table this replaces (operator-only
-- -- see the RLS policy above it in 20260806034517_rls_policies.sql).
-- Both gates deliberately added together in this same migration -- see
-- docs/SECURITY.md's two-gates entry (anomaly_thresholds/
-- customer_block_access) for why a policy with no grant, or a grant with
-- no policy, are the two ways this goes silently wrong.
create policy labour_actuals_read on labour_actuals for select
  using (current_role_name() = 'operator');
grant select on labour_actuals to authenticated;

-- Per (vintage, job_category) aggregate the dashboard and chat both read.
-- labor_cost/expense_cost kept SEPARATE (coalesced to 0, never summed
-- into one one column that could get misread as "cost") so cost_per_hour
-- is computed from labor_cost only -- summing them blindly would distort
-- $/hr for exactly the categories that receive expenses (Fertilize,
-- Disease Control, Irrigation, Other), per the ingestion project's
-- explicit requirement.
create view labour_actuals_by_category as
select
  vintage,
  job_category,
  coalesce(sum(hours) filter (where entry_kind = 'labor'), 0) as labor_hours,
  coalesce(sum(amount_usd) filter (where entry_kind = 'labor'), 0) as labor_cost,
  coalesce(sum(amount_usd) filter (where entry_kind = 'expense'), 0) as expense_cost,
  coalesce(sum(amount_usd) filter (where entry_kind = 'labor'), 0)
    + coalesce(sum(amount_usd) filter (where entry_kind = 'expense'), 0) as total_cost,
  case when coalesce(sum(hours) filter (where entry_kind = 'labor'), 0) > 0
    then sum(amount_usd) filter (where entry_kind = 'labor') / sum(hours) filter (where entry_kind = 'labor')
    else null end as cost_per_hour
from labour_actuals
group by vintage, job_category;

alter view labour_actuals_by_category set (security_invoker = true);
grant select on labour_actuals_by_category to authenticated;

-- Per-vintage coverage window (independent of job_category), so the
-- dashboard/chat can label "May-Dec 2023 (8 mo)" vs "July 2026 only (1 mo)"
-- honestly instead of implying every vintage covers a full season. Based
-- on entry_kind='labor' rows only -- expense_date coverage is a separate,
-- narrower question (July 2026 only) that doesn't need its own view.
create view labour_vintage_coverage as
select
  vintage,
  min(period_month) as first_month,
  max(period_month) as last_month,
  count(distinct period_month) as month_count
from labour_actuals
where entry_kind = 'labor'
group by vintage;

alter view labour_vintage_coverage set (security_invoker = true);
grant select on labour_vintage_coverage to authenticated;
