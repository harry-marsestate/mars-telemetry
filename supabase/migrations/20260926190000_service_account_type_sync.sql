-- Fix for 20260926180000 (2026-09-27): service accounts came out 'human'.
--
-- The first real `service-accounts.mjs create` failed its own check and
-- cleaned up after itself. Cause, read from supabase/auth's adminUserCreate
-- (internal/api/admin.go): inside one transaction GoTrue
--   1. INSERTs the user with app_metadata = {provider, providers} only,
--   2. then UpdateAppMetaData() -- UPDATE raw_app_meta_data -- merges the
--      caller's app_metadata (our account_type),
--   3. then Confirm() -- UPDATE email_confirmed_at.
-- handle_new_user() runs AFTER INSERT (step 1), before account_type exists,
-- so every profile was created 'human'. The offline tests modelled the
-- Admin API with app_metadata already in the INSERT, which is why they
-- passed; they now follow the real order.
--
-- Fix: user_profiles.account_type mirrors auth.users.raw_app_meta_data
-- ->> 'account_type', which only the service role and GoTrue can write.
--   * sync trigger: when an auth user's app_metadata account_type BECOMES
--     'service', its profile becomes 'service'. Step 2 above precedes the
--     confirmation in step 3, so the profile is already 'service' when the
--     confirmed_at webhook fires and notify-admin-approval skips it.
--   * guard: service -> human stays forbidden for everyone; human -> service
--     is allowed only when the auth row's app_metadata already says
--     'service'. An admin over REST still can't flip it, and nothing a user
--     can write (raw_user_meta_data) can cause it.
-- Promoting an existing ADMIN human by setting account_type in their
-- app_metadata fails closed: the never-admin constraint rejects the profile
-- update, which aborts the whole GoTrue update.

create function public.sync_service_account_type() returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.user_profiles p
     set account_type = 'service'
   where p.id = new.id
     and p.account_type = 'human';
  return new;
end;
$$;

-- Kept deliberately minimal (see 20260810165833's note: a throwing trigger on
-- auth.users can break sign-in flows), and its WHEN clause means it only runs
-- on the one transition it exists for.
create trigger on_auth_user_service_type
  after update of raw_app_meta_data on auth.users
  for each row
  when (new.raw_app_meta_data ->> 'account_type' = 'service'
        and (old.raw_app_meta_data ->> 'account_type') is distinct from 'service')
  execute function public.sync_service_account_type();

-- SECURITY DEFINER now: it reads auth.users, which an admin's REST session
-- (role authenticated) cannot.
create or replace function public.prevent_account_type_change() returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.account_type is distinct from old.account_type then
    if old.account_type = 'human' and new.account_type = 'service'
       and exists (select 1 from auth.users u
                    where u.id = new.id
                      and u.raw_app_meta_data ->> 'account_type' = 'service') then
      return new;
    end if;
    raise exception 'account_type cannot change after an account is created' using errcode = '42501';
  end if;
  return new;
end;
$$;

revoke execute on function public.sync_service_account_type() from public, anon, authenticated, service_role;
revoke execute on function public.prevent_account_type_change() from public, anon, authenticated, service_role;
