select
  w.vintage,
  w.block_id,
  b.label as block_label,
  b.acres,
  w.work_type,
  sum(w.hours) as total_hours,
  sum(w.cost_usd) as total_cost,
  sum(w.cost_usd) / b.acres as cost_per_acre
from {{ source('raw','work_events') }} w
join {{ source('raw','blocks') }} b on b.block_id = w.block_id
group by w.vintage, w.block_id, b.label, b.acres, w.work_type