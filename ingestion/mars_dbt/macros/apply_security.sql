{% macro apply_security_invoker(relation) %}
  {% if execute and relation is not none %}
    {% set rel_kind = run_query("select relkind from pg_class where relname = '" ~ relation.identifier ~ "'").columns[0].values()[0] %}
    {% if rel_kind == 'v' %}
      {% do run_query("alter view " ~ relation ~ " set (security_invoker = true)") %}
    {% else %}
      {% do run_query("alter table " ~ relation ~ " enable row level security") %}
      {% do run_query("drop policy if exists " ~ relation.identifier ~ "_read on " ~ relation) %}
      {% do run_query("create policy " ~ relation.identifier ~ "_read on " ~ relation ~ " for select using (true)") %}
    {% endif %}
  {% endif %}
{% endmacro %}