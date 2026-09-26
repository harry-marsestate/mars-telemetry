-- update_own_name() is SECURITY DEFINER and WRITES user_profiles for
-- auth.uid(). It was created with the default ACL -- EXECUTE for PUBLIC -- so
-- every role, including the new read-only mcp_reader (via its PUBLIC
-- membership), could call it: a gateway holding any user's claims could rename
-- that user. Its only caller is the signed-in web app (web/index.html,
-- `sb.rpc('update_own_name', ...)`), which runs as `authenticated`.
--
-- Narrow fix: EXECUTE for authenticated only. anon never had a uid for it to
-- act on. (The MCP tool transactions are also READ ONLY, so this was never
-- reachable through the function's own code path -- this closes it for the
-- gateway credential itself.)
revoke execute on function public.update_own_name(text, text) from public;
grant execute on function public.update_own_name(text, text) to authenticated;
