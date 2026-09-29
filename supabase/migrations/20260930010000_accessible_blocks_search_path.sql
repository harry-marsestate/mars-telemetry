-- accessible_blocks() was the only SECURITY DEFINER function in public with no
-- search_path, so it resolved blocks / customer_block_access / user_profiles /
-- current_role_name() through the CALLER's search_path -- the classic
-- definer-function hijack surface. Pin it to public like its siblings
-- (current_role_name, is_admin_user, domain_reality, ...). Its body names only
-- public objects plus the schema-qualified auth.uid(), so resolution is
-- unchanged. No inlining is lost: SECURITY DEFINER functions are never inlined
-- (the sensor_read policy's cost is unchanged). ALTER keeps its grants.
alter function public.accessible_blocks() set search_path = public;
