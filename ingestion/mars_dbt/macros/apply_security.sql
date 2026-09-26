{#
  Post-hook for every model (dbt_project.yml).

  Views: security_invoker = true, so the caller's own RLS applies.

  Tables: RLS on, plus the model's `<table>_read` SELECT policy -- built from
  the condition the model DECLARES in `config(meta={'read_policy': "..."})`,
  never a default. This macro used to write `using (true)` unconditionally,
  which silently reverted 20260810204144_approval_status_rls_gaps.sql's
  daily_weather fix on every dbt run and left daily_weather readable by
  pending/rejected accounts (docs/SECURITY.md, "daily_weather RLS drift").
  The declared condition must match the table's latest migration -- the
  migrations stay the source of truth; this only re-applies it after dbt
  rebuilds the table (a full-refresh drops the table and its policies).

  A table model with no declared read_policy fails the run loudly instead of
  guessing: `using (true)` fails open, and no policy at all fails silently
  (RLS on + zero policies = zero rows for everyone, the anomaly_thresholds
  failure mode).
#}
{% macro apply_security_invoker(relation) %}
  {% if execute and relation is not none %}
    {% set rel_kind = run_query("select relkind from pg_class where relname = '" ~ relation.identifier ~ "'").columns[0].values()[0] %}
    {% if rel_kind == 'v' %}
      {% do run_query("alter view " ~ relation ~ " set (security_invoker = true)") %}
    {% else %}
      {% set read_policy = (model.config.meta or {}).get('read_policy') %}
      {% if not read_policy %}
        {% do exceptions.raise_compiler_error(
          "apply_security_invoker: table model '" ~ relation.identifier ~ "' declares no read_policy. "
          ~ "Add config(meta={'read_policy': \"<condition from its latest migration>\"}) -- "
          ~ "this macro will not default to using (true).") %}
      {% endif %}
      {% do run_query("alter table " ~ relation ~ " enable row level security") %}
      {% do run_query("drop policy if exists " ~ relation.identifier ~ "_read on " ~ relation) %}
      {% do run_query("create policy " ~ relation.identifier ~ "_read on " ~ relation ~ " for select using (" ~ read_policy ~ ")") %}
    {% endif %}
  {% endif %}
{% endmacro %}
