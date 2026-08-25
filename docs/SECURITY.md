# Security notes

## RLS auto-enable gotcha

Every new table in `public` automatically gets RLS enabled by the ensure_rls
event trigger (rls_auto_enable()), but NO policy is auto-created - Postgres's
default with RLS on + zero policies is deny-all to everyone except the table
owner. This bit us once already: anomaly_thresholds was invisible to real
users for a while before we caught it via end-to-end testing.

customer_block_access sat in this exact dormant state until the Phase 6.8
approval-queue work needed to query it directly for a customer_account_id
collision check - now fixed, both grant and policy in place
(customer_block_access_admin_read, customer_block_access_grant), verified via
a simulated non-admin session (0 rows) and a simulated admin session (real
rows). Worth keeping this pairing on record together with the original
anomaly_thresholds incident, since they're the two failure modes of the same
two-gates principle and they fail with *different symptoms* - anomaly_thresholds
had a GRANT but no POLICY (RLS silently filters to zero rows, no error,
looks like "no data" rather than "no access"); customer_block_access had a
POLICY but no GRANT (a hard `permission denied for table X` error, thrown
even for an admin who should see everything). If you hit either shape again,
check the other gate first.

Known dormant instances (RLS on, no policy, not yet reachable by any
non-SECURITY-DEFINER path, so not currently broken - but WILL silently break
the moment something queries them directly):
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

## blocks.innovint_block_id - partial mapping, deliberately left incomplete

`blocks.innovint_block_id` (nullable, no default) cross-references local
`block_id`s against InnoVint's own block records, for future use pulling
real lot/vessel/component data from the InnoVint API. It is NOT a complete
mapping and should not be assumed to be:

- `B2` -> `block_LZ4E0PWYDM82N6OMX6R92JK5` (InnoVint "V2") and
  `B3` -> `block_W48YXVQJ1MK0PDLM30PRENL2` (InnoVint "V3") were set after
  checking acreage and other attributes lined up plausibly.
- `B1` was deliberately left `null`. Neither InnoVint candidate held up:
  `xxV1` (4.0 acres) is a closer acreage match than `Lower Block` (1.5
  acres), but its rootstock/trellising/clone data reads as an older
  heritage block with no recorded planting year, not a match for B1's
  2009-2014 planting. A third candidate (`06`) couldn't even be evaluated -
  no acreage or planted-year recorded on the InnoVint side at all.

RULE: do not backfill `B1`'s `innovint_block_id` on a coincidental
acreage/name match alone. A wrong mapping here is worse than no mapping -
it would silently pull another block's real InnoVint history (lot
records, vessel assignments, component makeup) onto B1's dashboard data
with no error or indication anything was mismatched. Only set it from a
confirmed source (e.g. someone at the winery confirming the InnoVint block
id directly).

## PostgREST's default 1000-row cap - silent truncation, not an error

An unfiltered `sb.from(table).select(...)` with no `.range()`/`.limit()`
caps out at 1000 rows and returns successfully - no error, no truncation
flag, just fewer rows than actually exist. Confirmed directly against
`lot_analyses` (1,405 real rows): a plain select returned exactly 1000,
silently dropping the rest. Because the query was ordered by `lot_name`
and the missing ~405 rows sorted last alphabetically, `Zinfandel, Howell
Mountain` (and one other lot) vanished entirely from the ferm panel's lot
dropdown - and, more seriously, from `fetchChartEligibleTypes()`'s global
chart-vs-card classification, which could have silently misclassified an
eligible analysis_type as card-only if the row proving otherwise happened
to sort past the cutoff.

Fixed for `lot_analyses` via a real paginated fetch (`fetchAllRows()`,
`web/index.html`) - loops `.range()` in 1000-row pages ordered by `id`
(the stable primary key, chosen only for deterministic pagination
boundaries, independent of whatever order a caller actually wants) until
a page returns fewer than 1000 rows.

Known dormant instance, NOT yet fixed: `sensor_readings` is 79,000+ rows
and every path that reads it in bulk (`buildSeriesReal`, `vSets`, etc.)
does so through the same unbounded-select pattern. Currently believed
safe only because every real call site filters by date range and/or
block first, keeping each individual query's result well under 1000 rows
in practice - not because pagination was actually added. That belief has
not been audited call-site by call-site. If a future query ever fetches
across a wide-enough range or drops a filter, this will fail exactly the
same way `lot_analyses` did: silently, not loudly.

RULE: any new unfiltered/large-table select needs either an explicit
`.range()` loop (see `fetchAllRows`) or a hard justification for why the
result is guaranteed to stay under 1000 rows - "it always has so far" is
not that justification, per this exact incident.

## anomalies_eval()'s latest_sensor DISTINCT ON key doesn't include sensor_id - a real reading can silently mask synthetic test data

`latest_sensor`'s `distinct on (metric_key, coalesce(block_id,''),
coalesce(tank_id,''))` picks one row per (metric, scope) at or before
p_as_of, ordered by `recorded_at desc`. `sensor_id` is not part of that
key. A synthetic reading inserted for testing (e.g. to prove a rule fires
on a specific value) that shares its exact `recorded_at` with a real
seed-data reading for the same metric/scope ties in that ordering, and
Postgres does not guarantee which row of the tie `DISTINCT ON` keeps - it
can silently be the real reading, not the synthetic one.

This surfaced concretely testing `frost_risk`'s `valid_to_doy` gate (Phase
12 Step 6): a synthetic 30°F reading inserted at `2022-05-10T06:00:00Z`,
the same timestamp as a real 57.93°F seed reading, produced "0 rows" from
`anomalies_eval()` - read at first glance as "the rule doesn't fire,"
when the actual cause was the tie picking the real warm reading over the
synthetic cold one. Using a distinct `sensor_id` did NOT fix this, since
`sensor_id` isn't in the dedup key at all - only moving `recorded_at` off
the real seed grid (a regular 3-hour `:00` grid) resolved it.

RULE: any synthetic/adversarial test reading inserted into
`sensor_readings` for verification (inside a transaction, rolled back
after) must use a `recorded_at` that does not coincide with any real
reading for the same `(metric_key, block_id, tank_id)` - an off-grid
minute offset (e.g. `:07` past the hour, not `:00`) is sufficient given
the seed data's regular cadence. A distinct `sensor_id` alone is not
enough. A "0 rows" / "doesn't fire" result during such a test should be
treated as ambiguous until this is checked, not taken as proof the code
path was actually exercised.

## Two independent panel repeat-render mechanisms - checking one doesn't confirm the other is safe

`web/index.html` has two separate ways a panel's `render()` can be
re-invoked against its existing, already-populated `body` element without
a full `renderTab()` rebuild in between: `SCOPED_RERENDER_SAFE` (a range-
button click on certain panels skips the full-tab rebuild and calls
`rerenderPanel()` directly) and `POLL_5MIN_PANEL_IDS` (a 5-minute
`setInterval` that calls `panelRuns[id]()` for a fixed list of panels,
regardless of `SCOPED_RERENDER_SAFE` membership). Both ultimately call the
same `panelRuns[p.id]` closure from `makePanel`, which reuses the `body`
element captured when the panel was first created - neither mechanism
gets a fresh container the way a full `renderTab()` does.

`lineChart`/`barChart` are safe under either mechanism - both replace
their container's content wholesale (`box.innerHTML=g`). The older,
hand-rolled `table()`/`strip()` helpers are not - both only
`box.appendChild(...)`, so a second invocation on the same body stacks a
duplicate underneath the first rather than replacing it.

This bit us twice, with the second incident specifically caused by
checking only one of the two mechanisms: the Solar/UV duplication fix
audited every `SCOPED_RERENDER_SAFE` panel and concluded (correctly, for
that mechanism) that no other panel shared the append-only pattern. But
`irrigblk` uses `table()`/`strip()` too, isn't in `SCOPED_RERENDER_SAFE`
(it has no `range` option, so that mechanism never applied to it) - and
*is* in `POLL_5MIN_PANEL_IDS`, which the earlier audit never checked.
Every 5 minutes it silently stacked a duplicate strip+table underneath
the last, invisible until enough polling cycles passed for it to be
visually obvious.

RULE: before trusting any panel using `table()`/`strip()` (or any other
append-only, non-self-clearing render path) as safe against duplication,
check it against BOTH `SCOPED_RERENDER_SAFE` and `POLL_5MIN_PANEL_IDS` -
not just the one that happens to be top of mind. A panel needs to clear
its container (`box.innerHTML=''`, matching the `lineChart`/`barChart`
convention) if it's a member of *either* set, not just one.
