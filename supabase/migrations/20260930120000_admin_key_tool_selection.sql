-- API keys: the admin UI chooses each key's tools (docs/SECURITY.md,
-- "API key tool scopes in the admin UI"). Until now admin_issue_agent_key
-- passed no tools, so every UI-issued key silently got the round-one five
-- (seen 2026-09-30: an svc-nightly-checks key refused get_system_health).
--
-- Same admin path as everything else here: SECURITY DEFINER wrappers that
-- check is_admin_user() and call the owner-only implementations; no table
-- grant. Health tools stay operator-only in the DATABASE: the
-- agent_api_keys_scope_guard trigger refuses them on any key whose owner
-- isn't an operator, for inserts and updates alike -- an admin can't
-- override it.

-- 1. Issue: tools are REQUIRED (no default). The old 3-argument signature is
--    dropped so a stale page fails loudly instead of silently defaulting.
drop function public.admin_issue_agent_key(uuid, text, integer);
create function public.admin_issue_agent_key(p_user_id uuid, p_label text, p_days integer, p_allowed_tools text[])
returns table (id uuid, key text, key_prefix text, label text, expires_at timestamptz, allowed_tools text[])
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_amr jsonb := auth.jwt() -> 'amr';
  v_signed_in_at double precision;
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_allowed_tools is null or cardinality(p_allowed_tools) = 0 then
    raise exception 'choose at least one tool for the key' using errcode = '22023';
  end if;

  select max((e ->> 'timestamp')::double precision) into v_signed_in_at
    from jsonb_array_elements(case when jsonb_typeof(v_amr) = 'array' then v_amr else '[]'::jsonb end) e
   where e ->> 'method' in ('password', 'oauth')
     and jsonb_typeof(e -> 'timestamp') = 'number';
  if v_signed_in_at is null or to_timestamp(v_signed_in_at) < now() - interval '10 minutes' then
    raise exception 'recent sign-in required: re-enter your password or re-authenticate with Google to create a key'
      using errcode = '42501', hint = 'reauth_required';
  end if;

  return query
  select i.id, i.key, i.key_prefix, i.label, i.expires_at, i.allowed_tools
    from public.agent_key_issue(
      p_user_id, p_label, p_days,
      coalesce(auth.jwt() ->> 'email', 'unknown email') || ' (' || auth.uid()::text || ') via web admin',
      false, p_allowed_tools
    ) i;
end;
$$;

-- 2. Change an active key's tools (audited in agent_api_key_scope_changes by
--    agent_key_set_tools). Same trust level as the expiry editor.
create function public.admin_update_agent_key_tools(p_id uuid, p_tools text[])
returns table (id uuid, key_prefix text, allowed_tools text[])
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_tools is null or cardinality(p_tools) = 0 then
    raise exception 'choose at least one tool for the key' using errcode = '22023';
  end if;
  return query
  select * from public.agent_key_set_tools(
    p_id, p_tools,
    coalesce(auth.jwt() ->> 'email', 'unknown email') || ' (' || auth.uid()::text || ') via web admin'
  );
end;
$$;

-- 3. The key detail view's tool-change history.
create function public.admin_list_agent_key_scope_changes(p_id uuid)
returns table (old_tools text[], new_tools text[], changed_by text, changed_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
  select c.old_tools, c.new_tools, c.changed_by, c.changed_at
    from public.agent_api_key_scope_changes c where c.key_id = p_id order by c.changed_at desc;
end;
$$;

-- 4. The catalogue for the picker, with each tool's preset group:
--    original = the round-one five, data = the other data tools,
--    health = operator-owned keys only.
create function public.admin_list_mcp_tools()
returns table (tool text, kind text, requires_operator boolean, preset text, note text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_admin_user() then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
  select t.tool, t.kind, t.requires_operator,
         case when t.kind = 'health' then 'health' when t.note like 'round one%' then 'original' else 'data' end,
         t.note
    from public.mcp_tool_catalogue t
   order by case when t.kind = 'health' then 3 when t.note like 'round one%' then 1 else 2 end, t.tool;
end;
$$;

revoke execute on function
  public.admin_issue_agent_key(uuid, text, integer, text[]),
  public.admin_update_agent_key_tools(uuid, text[]),
  public.admin_list_agent_key_scope_changes(uuid),
  public.admin_list_mcp_tools()
from public, anon, authenticated, service_role;
grant execute on function
  public.admin_issue_agent_key(uuid, text, integer, text[]),
  public.admin_update_agent_key_tools(uuid, text[]),
  public.admin_list_agent_key_scope_changes(uuid),
  public.admin_list_mcp_tools()
to authenticated;

notify pgrst, 'reload schema';
