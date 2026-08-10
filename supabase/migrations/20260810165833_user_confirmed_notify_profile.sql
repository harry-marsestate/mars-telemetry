alter table user_profiles add column confirmed_at timestamptz;

-- Deliberately minimal: research confirmed a trigger on auth.users that
-- throws (or does anything beyond a trivial write) can fail the underlying
-- auth.users write itself, breaking signup/confirm/login for the user
-- triggering it. No HTTP call, no other logic -- a single-column UPDATE
-- into user_profiles, guarded by the trigger's own WHEN clause so the
-- function body doesn't even run except on the email-confirmed transition.
-- The Database Webhook (configured separately, dashboard-side, on
-- user_profiles UPDATE where confirmed_at is not null) is what actually
-- notifies the admin -- this trigger only makes that column exist to
-- filter on.
create or replace function handle_user_confirmed() returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update user_profiles set confirmed_at = new.email_confirmed_at where id = new.id;
  return new;
end $$;

create trigger on_auth_user_confirmed
  after update of email_confirmed_at on auth.users
  for each row
  when (old.email_confirmed_at is null and new.email_confirmed_at is not null)
  execute function handle_user_confirmed();
