# Security notes

## RLS auto-enable gotcha

Every new table in `public` automatically gets RLS enabled by the ensure_rls
event trigger (rls_auto_enable()), but NO policy is auto-created - Postgres's
default with RLS on + zero policies is deny-all to everyone except the table
owner. This bit us once already: anomaly_thresholds was invisible to real
users for a while before we caught it via end-to-end testing.

Known dormant instances (RLS on, no policy, not yet reachable by any
non-SECURITY-DEFINER path, so not currently broken - but WILL silently break
the moment something queries them directly):
- customer_block_access, user_profiles (only reachable via SECURITY DEFINER
  helper functions today)
- tanks, block_lots (tied to deferred ferm/tanks/fruit real-data work)
- work_type_lookup (tied to deferred labour panel real-data work)
- stg_sensor_readings (dbt staging table, should probably stay deny-all
  permanently - not meant for app access)

RULE: whenever you wire up a new table to real frontend/RPC access, check
pg_policies for it FIRST, before assuming GRANT SELECT alone is sufficient -
grants and RLS policies are two independent gates, and satisfying one says
nothing about the other.

## Service-role-equivalent access points

Everything below bypasses RLS entirely - either by running as the function
owner (SECURITY DEFINER) or by using a service-role client directly. Treat
additions to this list carefully: each one is a deliberate hole punched
through the RLS model documented above, not just "another function."

- `current_role_name()` - SECURITY DEFINER. Reads `user_profiles.role`/
  `status` for `auth.uid()`. Backs RLS policies on multiple tables
  (sensor_readings, etc.) and the frontend's getCurrentUserRole().
- `accessible_blocks()` - SECURITY DEFINER. Reads `blocks`,
  `customer_block_access`, `user_profiles` to resolve which block_ids the
  calling user can see.
- `is_admin_user()` - SECURITY DEFINER. Reads `user_profiles.is_admin` for
  `auth.uid()`. Backs `admin_reads_all_profiles`/`admin_manages_profiles`.
- `handle_new_user()` - SECURITY DEFINER trigger on `auth.users` (AFTER
  INSERT). Inserts the matching `user_profiles` row.
- `handle_user_confirmed()` - SECURITY DEFINER trigger on `auth.users`
  (AFTER UPDATE OF email_confirmed_at). Writes `user_profiles.confirmed_at`
  only - kept deliberately minimal, since a trigger on auth.users that
  throws can break signup/login itself (see the migration's own comments).
- `notify-admin-approval` Edge Function (`supabase/functions/`) - uses
  `ctx.supabaseAdmin` (service-role client) to call
  `auth.admin.getUserById()`, resolving the new user's email since
  `user_profiles` has no email column. Server-to-server only
  (`auth: ["secret"]`), triggered by the user_profiles UPDATE Database
  Webhook.

## Two parallel API key systems - legacy JWT vs new secret/publishable

Supabase currently runs two separate credential systems side by side:
legacy JWT-based keys (`anon`/`service_role` - what's in `.env` and used
everywhere else in this project), and newer `publishable`/`secret` keys
(`sb_publishable_...`/`sb_secret_...`). They are not interchangeable, and
nothing about a JWT decoding successfully tells you which system a given
check is using.

This bit us on `notify-admin-approval`: Edge Functions built with the
`@supabase/server` scaffold's `withSupabase({ auth: ["secret"] })` validate
the *new* secret key via a literal string comparison against the
auto-injected `SUPABASE_SECRET_KEYS` env var - never a JWT decode of
`service_role`. A `service_role` JWT will decode as valid in the invocation
log (it genuinely is a well-formed, correctly-signed JWT), which looks like
proof the credential is right - but `"secret"` mode never inspects the
`Authorization` header or verifies any JWT at all, so it 401s regardless.
The failure has nothing to do with the key being wrong; it's the wrong
*kind* of key for that check.

RULE: any Database Webhook (or other caller) hitting a function that uses
`auth: ["secret"]`/`["publishable"]` needs the matching new-format key
(`sb_secret_...`/`sb_publishable_...`) in its `apikey` header - found at
Project Settings -> API Keys -> Secret keys (not the API Keys page's legacy
JWT section). The legacy `service_role`/`anon` keys will never satisfy
these auth modes, no matter how valid they are as JWTs.

## current_role_name() checks role, not approval - 'pending' is a real value

`current_role_name()` can return three things: `'operator'`, `'customer'`,
or `'pending'` (unapproved/rejected users resolve to `'pending'` regardless
of their stored `role` column - see `user_profiles.status`). Any policy or
SECURITY DEFINER function that checks `current_role_name() = 'operator'` or
similar is implicitly approval-safe, since `current_role_name()` can only
ever return `'operator'`/`'customer'` when `status = 'approved'`. But a
check like `current_role_name() != 'operator'` or anything that treats
`'pending'` as just "some other role" rather than "not yet a real user" can
silently grant real access to unapproved accounts.

This happened three times before it was caught: `sensor_read`'s
`min_role='all'` branch, `daily_weather_read`, and the `customer_block_access`
branch of `accessible_blocks()` were all written before the Phase 6 approval
system existed, and none of them were reconciled with it when `status` was
added. A genuinely pending Google-OAuth signup was rendering live vineyard
charts in the browser before this was fixed (see the
`approval_status_rls_gaps` migration).

RULE: when writing or reviewing any policy or SECURITY DEFINER function
that calls `current_role_name()`, treat `'pending'` as a real, distinct
value that must be explicitly excluded - not just "not operator" or "not
customer." Prefer an explicit allowlist (`current_role_name() in
('operator','customer')`) over a denylist (`current_role_name() !=
'pending'`), so a future fourth status value (e.g. `'suspended'`) fails
closed by default instead of silently falling through as granted.
