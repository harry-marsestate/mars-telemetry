alter table user_profiles add column status text not null default 'pending'
  check (status in ('pending','approved','rejected'));

-- A pending or rejected user resolves to role 'pending', which matches
-- nothing in any RLS policy -- so they authenticate successfully and get
-- zero rows back everywhere, without each policy needing a status check.
create or replace function current_role_name() returns text
language sql stable security definer
set search_path = public
as $$
  select case when status = 'approved' then role else 'pending' end
  from user_profiles where id = auth.uid()
$$;