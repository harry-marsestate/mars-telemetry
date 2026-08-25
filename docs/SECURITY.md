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

## daily_weather's date_trunc('day', ...) silently bucketed real sensor data into the wrong calendar day

`ingestion/mars_dbt/models/curated/daily_weather.sql` bucketed hourly
`sensor_readings` into days with `date_trunc('day', recorded_at)`. The
database session runs in UTC (confirmed via `show timezone`). Real
sensor timestamps (Open-Meteo, confirmed directly) represent genuine
Pacific local hours - `date_trunc` in a UTC session buckets by *UTC*
calendar day, so every day's 17:00-23:59 PDT (7 hours of true
Pacific-evening data, including some of the day's highest readings) was
silently landing in the *next* day's bucket. This corrupted
`tmax_f`/`tmin_f`/`dtr_f` and everything downstream of them
(`gdd_day`/`gdd_cumulative`/`vpd_kpa`/`et0_in` in `daily_derived`) for
any vintage backed by real, timezone-aware data.

Confirmed harmless for mock data only by coincidence, not by correctness:
mock's `recorded_at` values are generated on UTC-aligned hours as an
arbitrary internal day-numbering convention - they never claimed genuine
Pacific-local semantics in the first place, so UTC-day bucketing happened
to reproduce mock's own intended day boundaries. The same code that was
harmless for mock silently broke the instant real, genuinely
local-time-labeled data arrived - discovered only because a calibration
scalar, solved independently in Python against correctly-bucketed daily
min/max, failed to reproduce its target total when checked against the
database's own aggregation (off by ~120-140 GDD out of ~3000, not
obviously wrong at a glance).

Checked exhaustively before treating this as isolated, not assumed: grepped
every migration and dbt model for `date_trunc`, and every live Postgres
function body (`pg_proc.prosrc`) for the same pattern - found in exactly
one place. `series_bucketed()` (the other day/bucket mechanism, used by
charts) takes explicit caller-provided `generate_series` boundaries, not
`date_trunc` - a structurally different, unaffected approach. InnoVint's
`lot_analyses`/`vessels` (the only other real, timezone-aware data this
project ingests) have no day-bucketing logic anywhere in the SQL layer at
all - their timestamps are read directly, never truncated.

Fix: `(recorded_at at time zone 'America/Los_Angeles')::date::timestamptz`
instead of `date_trunc('day', recorded_at)` - correctly resolves the
Pacific calendar day, then re-represents it as a timestamptz at UTC
midnight, preserving `daily_weather.day`'s existing type/storage
convention so nothing downstream needs to change.

RULE: `date_trunc('day', ...)` (or any bare day/date truncation) on a
timestamptz column is only correct if the session timezone matches the
data's real-world timezone, or the data has no genuine timezone meaning
in the first place (as mock's didn't). Confirm which case applies before
trusting it - "worked fine on the data we had" is not evidence it's
timezone-correct if that data never actually exercised the distinction.

## dbt full-refresh on an incremental model drops dependent views AND their grants, silently

Running `dbt run --full-refresh` on `daily_weather` (an incremental
model) to pick up the date_trunc fix above did a real `DROP` + `CREATE`
of the underlying table, not an in-place update. Two consequences,
neither obvious in advance:

1. `daily_derived` (a plain view layered on top of `daily_weather` by
   migration, not a dbt-managed relation itself) was CASCADE-dropped
   along with the table it depends on. `to_regclass('daily_derived')`
   returned null after the refresh - the view was simply gone.
2. `grant select on daily_weather to authenticated` did not survive
   either, confirmed via `information_schema.role_table_grants`. This
   project's dbt setup has a post-hook
   (`models/macros/apply_security.sql`, `apply_security_invoker`) that
   re-applies RLS enable+policy on every model run - confirmed the
   `daily_weather_read` policy *did* survive - but that macro only
   handles RLS, not the separate table-level GRANT. Exactly the two-gates
   principle already on record above (anomaly_thresholds/
   customer_block_access), just triggered by a dbt refresh instead of a
   new-table creation, and landing on the opposite gate: the policy alone
   surviving without the grant is a hard `permission denied for table
   daily_weather` for every authenticated user, not a silent empty-rows
   result.

RULE: any `dbt run --full-refresh` (or equivalent drop+recreate) on
`daily_weather` will reproduce both of these. Re-run
`20260824000001_restore_daily_derived_post_refresh.sql`'s view-recreation
and grant statements (or an equivalent) after any such refresh - don't
assume dbt's post-hook covers everything a plain migration would have.

## Real soil data: two tracked frontend consequences, likely fixable together

Tracked here so neither is lost before the frontend phase of the
real-climate-data project. Both stem from the same root cause (ERA5-Land's
~11km grid can't distinguish this estate's three blocks, or resolve a
depth matching the mock's framing) and are likely worth fixing in the
same pass:

1. **Subtitle depth claim.** The mock Soil moisture/Soil temperature
   panels' subtitle says "Probes at 18 in." ERA5-Land's four fixed depth
   bands (0-7/7-28/28-100/100-255cm) don't include anything at 18in
   (~46cm), and the real-data backfill deliberately uses `0_to_7cm`
   specifically because that's the only band actually validated during
   reconnaissance (confirmed non-null at this site's coordinates) -
   using a deeper, unvalidated band just to preserve the old "18 in"
   framing would have reintroduced an unvalidated metric. Once the
   frontend switches these panels to real data, the subtitle needs to
   change to reflect the real depth (surface, 0-7cm), not keep claiming
   a depth this data was never actually sourced from.

2. **block_id mismatch.** The Soil Moisture panel queries per-block
   (`block_id in ('B1','B2','B3')`, three separate lines). Real soil data
   is intentionally stored estate-level (`block_id=null` - see the
   climate-calibration schema migration's reasoning: ERA5-Land's grid
   cell cannot distinguish three blocks spanning well under a mile).
   Confirmed directly (Phase 2 browser check, 2023 vintage, mock still
   present at the time): the per-block filter simply never matches a
   null block_id, so real soil rows are invisible to this chart. Status
   update post-Phase-3 (mock now deleted, confirmed via the Phase 3
   browser check): the panel no longer silently falls back to mock - it
   renders genuinely empty for 2022-2025, since nothing in
   `sensor_readings` matches its per-block query anymore. Not a
   rendering bug, but a real, now-visible gap between what's in the
   database and what the chart can currently query - needs a frontend
   change (collapse to a single estate-level line, or an equivalent)
   before real soil data becomes visible at all.

## Milestone: real-climate-data project, 2022-2025 mock replacement complete

No code diff accompanies this entry - the work it records was almost
entirely live-database operations (DELETE, dbt refresh, restoration SQL),
not file changes, so this note is the durable record of what happened.
`git log` covers the schema/ingestion-code side; this covers the rest.

**What was replaced.** For vintages 2022-2025, `air_temp`, `soil_moisture`,
and `soil_temp` mock rows (71,904 total: `source_system in
('weather_station','soil_probe')`, scoped precisely by `metric_key` too,
since `weather_station` is shared with six other still-mock metrics) were
deleted and replaced with real Open-Meteo/ERA5 data at the estate's
confirmed coordinates and elevation (38.603091360858635,
-122.45867651725105, 670m/2200ft). GDD and DTR are calibrated per-vintage
against real, same-year Napa Valley Grapegrowers Growing Conditions
Report figures for Angwin where one exists (2023: 3576, 2024: 4058;
verified against the production `daily_derived` view post-deletion, not
just an ad-hoc query: 3576.0006/4058.0007); 2022 and 2025 borrow the
2023/2024 average scalar, flagged `confidence='borrowed'` in
`vintage_climate_calibration`. Air temp itself, VPD, ET0, and soil stay
uncorrected, per the approved design - only GDD/DTR carry the
Grapegrowers calibration. 2026 deliberately stays on the existing
mock/live pipeline (still an active season, no report exists yet).
Humidity/wind/solar/uv/precipitation deliberately stay mock too - never
validated, out of scope for this pass.

**Two real bugs found and fixed along the way, not routed around:**

1. `daily_weather.sql` bucketed days by UTC (`date_trunc('day',
   recorded_at)`) in a UTC-session database, silently misattributing 7
   hours of genuine Pacific-evening data to the wrong calendar day every
   day, for any real (timezone-aware) data. Harmless for mock only by
   coincidence - mock's own UTC-aligned convention never claimed real
   timezone semantics. Full writeup and the generalizable rule above.
2. Real `soil_moisture` was stored as ERA5's native 0-1 volumetric-water-
   content fraction against an app-wide 0-100 percentage convention -
   would have read as permanently, catastrophically dry. Found during
   Phase 2 validation, not after the fact. Corrected in place (20,544
   rows, precisely scoped, verified) and fixed in the ingestion script
   itself so a rerun can't reintroduce it.

**One known, tracked, now-visible consequence:** the Soil Moisture/Soil
Temperature panels render empty for 2022-2025 (see the block_id-mismatch
entry directly above) - expected, already tracked before Phase 3 ran, not
a surprise this milestone is discovering for the first time.

**Verification discipline this milestone leaned on:** every step checked
against a real, independent reference before being trusted - CSV-vs-DB
row reconciliation before the DELETE, the DELETE's own count pre-checked
against that reconciliation, the production view (not a scoped query)
re-checked against the original calibration targets after the dbt
refresh, and a live browser check with a throwaway account after
everything else passed. Nothing here was accepted on "looks right" alone.
