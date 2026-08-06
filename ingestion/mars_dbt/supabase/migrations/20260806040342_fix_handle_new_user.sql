create or replace function handle_new_user() returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into user_profiles (id, full_name, role)
  values (new.id, new.raw_user_meta_data->>'full_name', 'customer');
  return new;
end $$;