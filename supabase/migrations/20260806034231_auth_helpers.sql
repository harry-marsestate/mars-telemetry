create function current_role_name() returns text language sql stable security definer as $$
  select role from user_profiles where id = auth.uid()
$$;

create function accessible_blocks() returns setof text language sql stable security definer as $$
  select block_id from blocks
  where current_role_name() = 'operator'
  union
  select block_id from customer_block_access
  where customer_account_id = (select customer_account_id from user_profiles where id = auth.uid())
$$;