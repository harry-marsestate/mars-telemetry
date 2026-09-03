-- Adds first_name/last_name to user_profiles (Feature A), plus the two
-- guardrails Feature B's account-editing needs. full_name is kept as-is
-- (still populated by handle_new_user() below, preserving the provider's
-- raw string) but nothing in the app reads it after this migration --
-- see docs/SECURITY.md for why it wasn't converted to a generated column
-- or dropped outright.

alter table user_profiles add column first_name text;
alter table user_profiles add column last_name text;

-- One-time backfill for the small number of existing rows with a clean
-- "First Last" full_name -- checked live: exactly 4 rows today, all
-- exactly two space-separated tokens, no 3+-token names in real data.
-- Every other row (full_name null) stays null and is correctly caught by
-- the new login gate -- this is not trying to be clever about the 8
-- nameless rows, just not needlessly re-gating the 4 that already have
-- good data.
update user_profiles
set first_name = split_part(full_name, ' ', 1),
    last_name  = trim(substring(full_name from position(' ' in full_name) + 1))
where full_name is not null and position(' ' in full_name) > 0;

-- handle_new_user(): now derives first_name/last_name too, for both
-- providers, in priority order:
--   1. raw_user_meta_data->>'first_name'/'last_name' -- the new email/
--      password signup form passes these explicitly via signUp()'s
--      options.data.
--   2. ->>'given_name'/'family_name' -- the correct source if a provider
--      supplies them. Checked live: this project's real Google rows do
--      NOT have these keys today (only full_name/name) -- so this branch
--      is forward-compatible, not currently exercised, and that's fine.
--   3. Split full_name/name on the first space -- the live case for every
--      real Google signup today, and the same logic the backfill above
--      uses, so a signup arriving right after this migration is treated
--      identically to the rows just backfilled.
-- Each of first_name/last_name is filled independently (not one
-- all-or-nothing fallback block), so a provider supplying only one of
-- given_name/family_name still gets the other derived from the combined
-- name rather than left null unnecessarily.
create or replace function handle_new_user() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_full_name text := new.raw_user_meta_data->>'full_name';
  v_name      text := coalesce(v_full_name, new.raw_user_meta_data->>'name');
  v_space     int  := 0;
  v_first     text := nullif(trim(coalesce(new.raw_user_meta_data->>'first_name', new.raw_user_meta_data->>'given_name')), '');
  v_last      text := nullif(trim(coalesce(new.raw_user_meta_data->>'last_name',  new.raw_user_meta_data->>'family_name')), '');
begin
  if v_name is not null then
    v_space := position(' ' in v_name);
  end if;
  if v_first is null then
    v_first := case when v_space > 0 then split_part(v_name, ' ', 1) else v_name end;
  end if;
  if v_last is null and v_space > 0 then
    v_last := trim(substring(v_name from v_space + 1));
  end if;

  insert into user_profiles (id, full_name, role, first_name, last_name)
  values (new.id, v_full_name, 'customer', nullif(trim(v_first), ''), nullif(trim(v_last), ''));
  return new;
end $$;

-- Self-service name update (Feature A's login gate, and any future
-- "edit my own name" affordance). SECURITY DEFINER, deliberately narrow:
-- only first_name/last_name are settable, and only for auth.uid()'s own
-- row -- there is no parameter through which role/is_admin/status/
-- customer_account_id could be smuggled in, unlike a bare column-level
-- GRANT (verified live this doesn't actually restrict anything here,
-- since `authenticated` already has a table-wide UPDATE grant from the
-- admin_manages_profiles migration -- see docs/SECURITY.md). Left at the
-- default PUBLIC execute grant, matching every other function in this
-- file (current_role_name/is_admin_user/etc. are all ungranted-by-name
-- too) -- safe for an anon caller regardless, since auth.uid() is null
-- for one and the WHERE clause then matches zero rows.
create or replace function update_own_name(p_first_name text, p_last_name text) returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if nullif(trim(p_first_name), '') is null or nullif(trim(p_last_name), '') is null then
    raise exception 'first and last name are both required';
  end if;
  update user_profiles
  set first_name = trim(p_first_name), last_name = trim(p_last_name)
  where id = auth.uid();
end $$;

-- Self-demotion guardrail for Feature B's account editor. A bare RLS
-- WITH CHECK cannot express this -- policy expressions only see the
-- proposed NEW row, with no OLD reference, so "block is_admin true->false
-- for your own row" needs a BEFORE UPDATE trigger instead. Verified live
-- (rolled-back transaction): blocks a bare is_admin:false self-update,
-- STILL blocks it when is_admin is bundled with another field in the
-- same UPDATE statement (not bypassable by bundling), and correctly
-- allows is_admin:true->true alongside other field changes. Scoped by
-- OLD.id = auth.uid() -- an admin editing a DIFFERENT admin's row is
-- unaffected, by construction of that condition, not a separate check.
create or replace function prevent_self_admin_removal() returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.id = auth.uid() and old.is_admin = true and new.is_admin = false then
    raise exception 'cannot remove your own admin status';
  end if;
  return new;
end $$;

create trigger guard_self_admin_removal before update on user_profiles
for each row execute function prevent_self_admin_removal();
