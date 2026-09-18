-- Additive: a month-grained sibling to labour_actuals_by_category, for
-- the chat tool's new per-month query support (get_labour_summary's
-- optional period_month parameter -- see supabase/functions/chat/tools.ts).
-- Does NOT touch labour_actuals, labour_actuals_by_category,
-- labour_vintage_coverage, or domain_reality() -- confirmed by investigation
-- (docs/SECURITY.md) that labour_actuals.period_month is already a correct,
-- row-level column for every source ingested so far, so this is a pure
-- aggregation-layer addition, not a schema/data change.
--
-- Same column shape as labour_actuals_by_category (labor_hours, labor_cost,
-- expense_cost, total_cost, cost_per_hour -- same labor-cost-only $/hr rule,
-- same reasoning: expenses have cost but no hours, so blending them into
-- cost_per_hour would distort the categories that receive folded-in
-- expenses), with period_month added as a third grouping column alongside
-- vintage and job_category.
create view labour_actuals_by_month as
select
  vintage,
  period_month,
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
group by vintage, period_month, job_category;

alter view labour_actuals_by_month set (security_invoker = true);
grant select on labour_actuals_by_month to authenticated;
