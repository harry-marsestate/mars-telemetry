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
- `insights-scan` Edge Function (`supabase/functions/`) - uses
  `ctx.supabaseAdmin` (service-role client) to read across
  sensor_readings/daily_derived/harvest_receipts and write `insights`
  directly, bypassing RLS on both the read and write side. `insights`
  itself has no insert/update policy at all -- the service-role client is
  the ONLY writer, by design, not an oversight to close later. Server-to-
  server only (`auth: ["secret"]`), triggered exclusively by
  pg_cron -> pg_net on the weekly schedule (see the insights-engine
  migration) -- never reachable by a browser session. Getting this
  working also surfaced that `service_role` had no table-level GRANTs
  anywhere in this project at all, BYPASSRLS notwithstanding -- see the
  dedicated entry near the end of this file.

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

## block_innovint_map - time-scoped mapping (supersedes blocks.innovint_block_id)

**The RULE below still stands unchanged. What changed is that B1 now meets
its bar** - this entry is superseded, not deleted, so the reasoning that
kept B1 unmapped for months stays on record.

RULE: do not map a local block to an InnoVint block on a coincidental
acreage/name match alone. A wrong mapping is worse than no mapping - it
silently pulls another block's real InnoVint history (lot records, vessel
assignments, component makeup) onto that block's dashboard data with no
error. Only map from a confirmed source (e.g. someone at the winery
confirming the InnoVint block id directly).

**B1 -> `xxV1` is now mapped, for vintages <=2023 only.** This is not the
coincidental backfill the rule forbids:

1. Winery-confirmed directly - `xxV1` IS Block 1, as it existed before the
   Zinfandel was pulled and replanted to Cab Sauv/Cab Franc/Petit Verdot.
2. Independently corroborated by data the original investigation didn't
   have: Zinfandel grower receipts exist for 2022 (4.802t) and 2023
   (10.469t, FL-23-ZI-ME-V1, 2023-09-27) and then stop entirely. The 2024
   harvest is Cabernet from V2/V3 only, and there are no 2025+ receipts at
   all - consistent with young replanted vines not yet cropping.
3. `xxV1` is `archived: true` in InnoVint while V2/V3 are not.

**Correcting the original reasoning:** this entry previously rejected `xxV1`
partly because its heritage attributes didn't match "B1's 2009-2014
planting." Planting year was never a reliable discriminator in this dataset
- the *confirmed* B2/V2 mapping disagrees by 4 years (local 2006 vs InnoVint
2002) and B3/V3 by 6 (2006 vs 2012). Acreage was similarly weak: B1/xxV1
differ by 8.1%, but confirmed B2/V2 differ by 29.5%. Do not resurrect either
signal as evidence for or against a future mapping.

**The <=2023 cutover is PROVISIONAL.** The exact replant year is not fully
confirmed. It lives in exactly one place - `valid_to_vintage` on B1's row -
and revising it is a one-row UPDATE. No code, migration, or frontend
constant encodes a B1 cutover year. Keep it that way.

**2024+ B1 is deliberately unmapped**, which is the whole point of the time
scoping: an unbounded mapping would attribute the pre-replant Zinfandel
parcel to today's Cabernet block - precisely the failure the RULE describes.
When InnoVint gains a post-replant B1 block object, add a SECOND row with
`valid_from_vintage` set; do not edit the existing one.

**Known consequence, expected not accidental:** adding B1 to the mapping
makes 8 single-component lots (the 2022/2023 Zinfandel and lees lots) newly
resolve to `block_id='B1'` in `lot_analyses` and `vessels`, where they
previously landed NULL. That data was always Block 1's - it is newly
visible, not newly correct - but it will appear in the ferm panel's lot
dropdown the next time `analyses_sync` runs.

Still unmapped and still unevaluable: InnoVint's `06` (no acreage or
planted year recorded at all) and `Lower Block` (1.5 acres).

## Block acreage: the Silverado Farming Company survey is the golden source

The winery confirmed the Silverado Farming Company parcel survey as
authoritative for block acreage. It supersedes BOTH prior sources, which
disagreed with it and with each other:

                 old local seed    InnoVint    survey (authoritative)
    B1               3.7             4.0              2.99
    B2               2.2             2.85             2.91
    B3               1.4             1.4              1.45
    estate           7.3             8.25             7.35

B1's variety split comes from the survey's sub-block breakdown: MRS-1A 1.12
+ MRS-1B 0.98 = 2.10 Cab Sauv, MRS-1C 0.60 Cab Franc, MRS-1D 0.29 Petit
Verdot, summing to 2.99.

Applied to every source of truth together, since three existed: `BLOCKS[]`
in `web/index.html`, `seed-data/blocks.csv` + `seed-data/block_lots.csv`,
and the live `blocks`/`block_lots` tables (migration
`20260830000001_survey_acreage_correction`). `labour_summary` is a VIEW over
`blocks.acres` (confirmed `pg_class.relkind='v'`), so its `cost_per_acre`
reflected the change immediately with no dbt run - unlike `daily_weather`,
it carries no refresh hazard.

**Note InnoVint's acreage was not merely imprecise - for B1 it was stale.**
`xxV1`'s 4.0 acres describes the pre-replant Zinfandel parcel, not today's
2.99-acre Cab Sauv/Cab Franc/Petit Verdot planting. This is why the fruit
panel briefly carried its own `FRUIT_YIELD_ACRES` constant (InnoVint acreage
for a panel sourced from InnoVint). That constant is now REMOVED: the right
fix was correcting the source of truth, not giving one panel a private
basis. Every panel uses `B(id).acres` again.

**Second independent confirmation that `xxV1` is pre-replant B1.** The entry
above rests on the winery's word plus the receipt timeline (Zinfandel
receipts stopping after 2023). The survey adds a third, structural check -
vine spacing and rootstock, against InnoVint's `rowWidth`/
`spaceBetweenVines`/`rootStock`:

- B2 -> `V2`: survey 8x5, rootstock 101-14; InnoVint rowWidth 5.0ft,
  spaceBetweenVines 8.0ft, rootStock `101-14`. AGREES.
- B3 -> `V3`: survey 8x3, rootstock 110R; InnoVint rowWidth 3.0ft,
  spaceBetweenVines 8.0ft, rootStock `110R`. AGREES.
- B1 -> `xxV1`: survey 7x4, rootstock 110R; InnoVint rowWidth 6.0ft,
  spaceBetweenVines 8.0ft, rootStock `St George, 101-14`. DISAGREES.

The disagreement is corroboration, not a contradiction: the survey describes
the post-replant B1 while `xxV1` records the parcel as it was before. Both
confirmed mappings agree on spacing and rootstock; the one block that was
replanted is the one that doesn't - exactly the pattern the replant predicts.
Contrast with planting year and acreage, which the entry above establishes
were never reliable discriminators in this dataset. Spacing and rootstock
ARE reliable where both sides describe the same planting - a genuinely
better signal than the two that misled the original investigation.

### Still open, deliberately not fixed with this correction

- **Row counts.** The survey shows MRS-1A rows 1-27 and MRS-1B rows 5-27 -
  overlapping on 23 of 27 rather than partitioning. Likely a transcription
  artifact in the source document. `BLOCKS[].rows` (B1 = 60) and
  `blocks.row_count` are UNTOUCHED. Do not propagate the survey's row
  numbering into any row-count field until it is confirmed.
- **No local spacing/rootstock fields exist.** Grepped `web/index.html`,
  `seed-data/`, `supabase/migrations/`, `ingestion/mars_dbt/`: the only hits
  are CSS `letter-spacing`. Live `blocks` is `block_id, label, designation,
  acres, row_count, planted, aspect, elev_ft, color, innovint_block_id`.
  Storing the survey's spacing/rootstock would need a new column AND a new
  `BLOCKS[]` key - not added speculatively, and the cross-check above was
  done against InnoVint's copy of those fields, not a local one.
- **B1 `planted: '2009-2014'` is still wrong** (see the entry above),
  pending the winery's real replant year. The acreage correction does not
  touch it.
- **`blocks.innovint_block_id` still exists**, superseded by
  `block_innovint_map` but not dropped: `lot_analyses.block_id` carries a
  `comment on column` naming it (migration `20260811215238`), which needs
  re-issuing in the drop migration.

## fmt(7.35, 1) is "7.4", not "7.3" - don't hardcode a header to match a computed value you haven't run

The survey's own cover figure displays "7.3 acres". The obvious move was to
hardcode the estate header to match. That would have been wrong, and the
reason is subtler than plain float error:

    2.99 + 2.91 + 1.45   = 7.3500000000000005   (not exactly 7.35)
    fmt(sum, 1)          = "7.4"
    fmt(7.35, 1)         = "7.4"     <- even the EXACT literal rounds up
    (7.35).toFixed(1)    = "7.3"     <- and toFixed disagrees with fmt

Two independent effects stack. The float sum lands just above 7.35, and
`fmt` uses `toLocaleString`, which rounds half-UP on the decimal value - so
even a mathematically exact 7.35 renders "7.4". `toFixed` rounds the binary
value and gives "7.3", so the two rounding paths in this codebase disagree
with each other on the same number.

Had the header been hardcoded to "7.3" to match the survey, it would have
sat next to a computed legend reading "7.4 acres" - two figures for the same
estate on the same screen, with no error anywhere.

Fixed by raising precision rather than by matching a rounded value:
`acresOf()` now uses `.toFixed(2)` and all 8 acreage display sites use
`fmt(..., 2)` (legend chips + total, map tooltip, filter meta, labour table
row + total, and "Acres in view" in BOTH the real and mock fruit panels).
Both hardcoded header strings read "7.35 acres". At 2dp the displayed
per-block values visibly sum to the displayed total (2.99 + 2.91 + 1.45 =
7.35), which they did not at 1dp (3.0 + 2.9 + 1.5 = 7.4). `.toFixed(2)` also
collapses the float artifact before `fmt` ever sees it, so `acresOf(['B1',
'B2','B3']) === 7.35` is exactly true.

RULE: don't assume a "clean" decimal like X.Y5 rounds the way you expect at
1dp. Check actual `fmt()` output before hardcoding any header string to
match a computed one - and be aware `fmt`/`toLocaleString` and `toFixed`
round X.Y5 differently in this codebase. When a source document's own
rounding conflicts with the app's, raise the app's precision to match the
source's underlying numbers rather than hardcoding the source's rounded
display.

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

(A third, related item - the VPD/ET0 subtitle - is tracked separately
below, since its trigger is the humidity/precipitation/solar round, not
the soil round.)

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

## Real humidity data (pending): VPD/ET0 subtitle will go stale once it lands

Tracked now, before it becomes relevant, per the same discipline as the
two soil items above - recorded ahead of the change that triggers it,
not discovered as a surprise afterward.

`getDataSourceLabel()`'s `derived` branch (VPD, ET0) currently reads
"Derived metric - from air temperature and humidity" / "...temperature,
humidity, wind, and solar radiation" regardless of vintage - deliberately
not given a `REAL_CLIMATE_VINTAGES` branch during the air_temp/soil round,
because at that point only one of VPD's two inputs (air_temp) was real;
humidity was still mock, so labeling VPD as real would have overclaimed.

Once the humidity backfill in progress now (this round: precipitation,
humidity, solar) completes Phase 3, that reasoning inverts: air_temp and
humidity will both be real for 2022-2025, so VPD becomes a derived metric
with two real inputs, and its subtitle should say so. ET0 is not fully
resolved by this round - it also depends on wind and solar; solar is in
this round, but wind stays mock indefinitely (no usable real-world
reference found for this site or nearby - see the wind investigation
below), so ET0 will remain a mixed real/mock derivation even after this
round closes, and its subtitle should reflect that honestly rather than
flipping to a fully-real claim it hasn't earned. (Wind stays mock
indefinitely: three real sources checked directly - Angwin-Parrett Field
airport K2O3, confirmed absent from Iowa Mesonet's monitored CA ASOS
network with zero historical archive; CIMIS Angwin #79, elevation-matched
but disconnected since 1996, decades before this project's 2022-2025
window; CIMIS's only currently-active Napa County station, Oakville #77,
at 190ft valley-floor elevation versus this site's 2200ft - no usable
reference found, treated the same as UV's unfixable gap.)

## series_bucketed() and daily_weather.sql silently averaged mock and real readings together

**The bug.** Neither `series_bucketed()` (the live Postgres function every
chart calls) nor `daily_weather.sql`'s `hourly` CTE filtered by
`source_system`. Both simply aggregated (`avg`/`sum`/`max`/`min`) every
`sensor_readings` row matching a given metric/vintage/bucket, regardless
of which source produced it. This was harmless while air_temp and soil
were the only real metrics, because their mock rows had already been
deleted in Phase 3 of that round - there was nothing left to blend with.
It became live and active the moment this round's Phase 1 (precipitation/
humidity/solar) inserted real rows alongside mock rows that were still
present, waiting for their own Phase 3.

**How it was found.** During this round's Phase 2 browser check, the
2023 Relative Humidity chart rendered a visibly jagged, inconsistent
shape rather than a clean diurnal curve - the tell that two differently-
sampled datasets (mock's 3-hourly grid for 2022-2024, real's hourly ERA5
data) were being pooled into the same buckets. A direct query confirmed
it wasn't a rare edge case: 1,709 of 5,139 hourly humidity readings for
2023 collided at the identical timestamp, and even non-colliding hours
were pooled together at wider (5D/30D) bucket widths. `daily_weather.sql`
had the same defect but was dormant rather than active - its incremental
materialization strategy only recomputes days after its stored max, so
already-materialized 2022-2025 rows wouldn't blend until some future
`--full-refresh` (for any reason) recomputed them.

**The fix.** Real data, when present for a given (metric, vintage[,
block]), now fully supersedes mock for that combination rather than being
merged with it - matching the mental model Phase 3 deletion already
assumes, effectively behaving as if Phase 3 had already run. Baked into
both functions directly rather than passed as a caller parameter: every
call site across the app wants the same policy (best available real
signal, never mock specifically), so centralizing it removes the
recurrence risk of a future call site forgetting to ask for it. This is
the same shared-infrastructure precedent already set by `daily_derived`'s
calibration scalar (`coalesce(c.scalar,1)` applied via LEFT JOIN, not
supplied per caller).

Two separate implementations were required, not one, because the two
code paths differ structurally:
- `series_bucketed()` is a live SQL function, re-evaluated per request -
  its fix is a WHERE-clause EXISTS check, scoped to the specific
  `p_block` being queried (falling back to estate-level real rows via
  `block_id is null`) rather than to metric+vintage alone. This matters
  for a hypothetical future per-block real source rolled out unevenly
  across blocks - a metric-vintage-only check would incorrectly suppress
  still-valid mock data for a block that hasn't received real data yet.
  Today it collapses to the same result as a block-agnostic check, since
  every authoritative row today is estate-level (`block_id is null`) and
  matches every `p_block` via that fallback branch.
- `daily_weather.sql` is a dbt-materialized incremental table, only
  recomputed on `dbt run`/`--full-refresh` - its fix is a `real_scope`
  CTE pre-filtering `hourly` before aggregation. It does NOT need the
  block-fallback logic: this model has no block dimension at all, by
  construction (it never carries soil, the one metric where block_id has
  mattered), so vintage+metric_key scoping is correct today and stays
  correct under any future per-block real source.

`'open_meteo_era5'` is hardcoded as the one authoritative source in both
places today; a future second real source would need adding to both,
kept in sync manually since the two implementations can't share code.

**Verification performed.**
1. Checksummed `series_bucketed()` output for every metric with no real
   counterpart (wind_speed, uv, cellar_temp, cellar_rh, irrigation_volume,
   ferment_brix, ferment_temp) before and after the fix - all seven
   matched byte-for-byte (7,129 total rows), confirming zero behavior
   change for anything the fix wasn't meant to touch.
2. Compared `series_bucketed()`'s humidity/solar 2023 output against a
   manual real-only aggregate, hourly buckets across the full season - 0
   mismatches out of 5,113 buckets for each metric.
3. After `dbt run --full-refresh --select daily_weather` (which, as
   documented above, cascade-dropped `daily_derived` and its grant again
   - restored via the existing restoration migration's SQL), compared
   `rh_avg`/`solar_avg` for all 214 days of 2023 against a manual
   real-only daily aggregate - 0 mismatches; `tmax_f`/`tmin_f`
   (already real-only pre-fix) also showed 0 mismatches, confirming the
   refresh didn't regress anything already correct.
4. Browser re-check: the 2023 Relative Humidity chart now renders a
   clean, single diurnal curve, visibly different from the jagged shape
   that first surfaced the bug.

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

## Browser-check methodology: hard reload before trusting the result

Verifying the `soilSets()` fix (block_id mismatch, above), the first
browser pass showed the panels still rendering pre-fix behavior - three
per-block lines and "No readings in this period" for a real vintage -
even though the underlying `series_bucketed()`/query logic was already
correct. Chrome had cached the pre-fix `index.html`/JS from an earlier
check earlier in the same session; a hard reload (not a normal
navigation) resolved it immediately, and the correct post-fix behavior
was there all along.

Standing step for any future browser check of a JS/frontend change: hard
reload before taking a rendered result as evidence, not just on the first
load of a session. A normal navigation to the same URL can silently serve
a stale cached script, and the resulting "still broken" observation is
indistinguishable at a glance from a real regression - it cost a false
start here before the cache was identified as the cause rather than the
fix being wrong.

## Track 2 (irrigation) Phase 3: a DELETE scoped too broadly, caught, and the reasoning that led to permanent deletion over a display-only fix

**The mistake.** Phase 3 for Track 2 (irrigation) deleted mock
`flow_meter` rows for `vintage IN (2023,2024)` with no `block_id` filter.
That was wrong for one cell: B1/2024 has no real replacement (Block 1
was replanting that year, absent from the source files entirely - see
the Phase 1 commit), so its mock row should have stayed as the block-aware
fallback `series_bucketed()` was built to prefer, per the soil fix
above. The delete briefly left B1/2024 with zero `irrigation_volume`
rows of any kind.

**Caught immediately**, before moving on to the next step: a post-delete
query grouped by vintage/block/source_system, expecting to see B1/2024
still present as `flow_meter`, and it was missing entirely. Restored the
214 rows from `seed-data/sensor_readings_2024.csv` via `\copy`, verified
byte-identical to the original.

**Then deliberately deleted again, permanently - this was not reverting
the fix.** The restore made B1/2024 render correctly in the vineyard
panels (mock fallback, exactly as designed), but that's not the whole
system: the chat feature answers questions from the data directly, and
there was no guarantee it reads through `series_bucketed()`'s block-aware
mock/real precedence logic the same way the charts do. If it queries
`sensor_readings` some other way, a restored mock row for B1/2024 could
surface as an unqualified irrigation figure - stale and wrong - while the
chart correctly showed the same block as a deliberate fallback. Two
surfaces disagreeing about whether B1/2024 has real data is worse than
one surface having no data at all. So the resolution was: precisely
re-verify the scope (`block_id='B1' AND vintage=2024 AND
metric_key='irrigation_volume' AND source_system='flow_meter'` - checked
directly before running anything, given the near-miss was specifically a
scoping error), then delete those exact 214 rows permanently.

**Verified after the final delete:**
1. B1/2024: 0 `irrigation_volume` rows, any source.
2. B2/B3/2024 and all of 2023 unaffected (`farm_irrigation_log`, correct
   row counts).
3. 2022/2025/2026 unaffected (`flow_meter` only, correct counts).
4. Browser check: the "Irrigation Volume Applied" panel for B1/2024 now
   shows a genuine empty state (unit badge "0/ac", zeroed axis, no bars)
   - not mock, not real.
5. Chat check, the specific thing this was protecting against: asked
   "How much irrigation was applied to Block 1 in 2024?" directly.
   Response: "No irrigation data returned for Block 1 in 2024 - all
   buckets are null... I don't have grounds to report a figure here." No
   stale mock number surfaced.

General lesson, not specific to irrigation: a block-aware mock fallback
is only safe to leave in place if *every* consumer of the data goes
through the same precedence logic. Where a second consumer (here, the
chat) reads the underlying table more directly, the fallback needs to be
an active decision confirmed for that consumer too, not assumed to
inherit correctness from the chart's own query path.

## Tracked future project (scoped, not started): full calendar year coverage

Everything real and mock in this project covers the growing season only
(Apr 1 - Oct 31). Expanding to Jan-Dec would involve:

- Re-running the Open-Meteo backfill for Nov-Mar across every
  already-backfilled metric (air_temp, GDD/DTR, soil_moisture/soil_temp,
  precipitation, humidity, solar) at the same confirmed
  coordinates/elevation - same phased structure (schema check,
  insert-alongside, validate, delete) as every prior round.
- Reconsidering whether the GDD/DTR calibration scalars - solved against
  Apr-Oct Napa Valley Grapegrowers season totals - extend cleanly to a
  full year, or whether off-season GDD/DTR needs its own reference (very
  likely near-zero GDD accumulation Nov-Mar at this elevation, but that's
  a claim to verify against a real source, not assume).
- Confirming, not assuming, whether irrigation genuinely has zero real
  off-season activity - plausible, since vineyards don't typically
  irrigate outside the growing season, but the Mars Irrigation source
  files should be checked for any Nov-Mar rows before treating the
  off-season as a real, confirmed gap rather than something to fill.
- Extending mock generation consistently for whatever stays mock (wind,
  UV, and anything not re-backfilled), using the same noise()-based
  logic already used for Apr-Oct rather than a different generator.

Not started. Flagging now so scope is on record before anyone assumes
Apr-Oct is the permanent boundary rather than a deliberate, revisitable
one.

## anomaly_thresholds "permission denied" for operators: looked like the grant/policy pattern above, wasn't - checked and ruled out RLS, root cause was two client-side resilience gaps

An operator session hit `permission denied for table anomaly_thresholds`
on the winery tab (cellar temperature/humidity panels showing "Panel
unavailable", winery Insights and Anomalies blank) - on its face the same
shape as the `anomaly_thresholds`/`customer_block_access` two-gates
incidents already on record above. It was not. Before touching anything,
checked for exactly that regression and ruled it out directly against the
live database, not migration files:

- `pg_policies`: `anomaly_thresholds_read` present, `using (true)`, role
  `{public}`.
- `information_schema.role_table_grants`: `authenticated` has `SELECT`.
- `information_schema.column_privileges`: all columns granted to
  `authenticated`.
- `set role authenticated; select * from anomaly_thresholds` succeeds
  directly in Postgres.
- 20 concurrent authenticated REST calls to `anomaly_thresholds` (real
  session JWT, real `apikey` header, not a superuser simulation): 20/20
  succeeded.
- `anomalies_eval()`: exactly one overload live (the 3-arg
  `p_tab default 'vineyard'` version from the consolidation migration),
  `EXECUTE` granted to both `PUBLIC` and `authenticated`.

Both gates from the original incident are intact and correctly paired.
This was never a grant/policy regression.

**What it actually was - two separate application-layer bugs, each
reproduced live:**

1. **`getThresholds()` (web/index.html) had a startup race with no
   retry.** `fetchThresholds()` fires eagerly at script-parse time,
   before Supabase JS is guaranteed to have restored the session from
   `localStorage`. Losing that race once - most likely right after a
   fresh interactive sign-in - sends the request as `anon`, which
   correctly lacks `SELECT` (anon is not meant to read this table
   unauthenticated), producing exactly `permission denied for table
   anomaly_thresholds`. `thresholdsPromise` memoized that failure
   permanently with no catch/reset, so the one race loss broke `cellart`/
   `cellarh` for the rest of the page's life - only a hard reload
   recovered. Reproduced deterministically (not inferred): monkey-patched
   `sb.from` to fail exactly once with this error, called the real
   `getThresholds()` twice - first call failed as expected, second call
   (unpatched, real table) retried fresh and succeeded, confirming the
   fix (`.catch(err => { thresholdsPromise = null; throw err; })`)
   resolves it without needing a reload.
2. **Winery's anomalies branch (`renderAnomalies`, the `tab==='winery'`
   case) had no fail-soft handling, unlike the vineyard branch right
   above it.** `anomalies_eval()` can genuinely hit a Postgres statement
   timeout under the concurrent request burst of a page load - already
   documented and already defended against in the vineyard branch via
   `Promise.allSettled` + log-and-continue. Confirmed live: a 10-way
   concurrent burst against `anomalies_eval` returned `57014 canceling
   statement due to statement timeout` on 8 of 10 calls; one real page
   load's vineyard call hit exactly this and degraded silently as
   designed, a different load's winery call hit it and blanked the whole
   panel (`if(error) throw error;`, no fallback). Verified the fix by
   intercepting `sb.rpc` to return a synthetic `57014` error for just the
   winery call and running the real `renderAnomalies('winery')` against
   it: no throw, client-side `RULES` hits still rendered, matching
   vineyard's existing behavior.

Deliberately left untouched: the `57014` timeout itself. It's an already
-accepted characteristic of the initial page-load burst (the vineyard
code comment predicted this before winery ever hit it), not something to
eliminate here - the fix makes both call sites survive it the same way,
not stop it from happening.

RULE: an `anomaly_thresholds`-shaped "permission denied" is not
automatically a repeat of the grant-without-policy/policy-without-grant
incidents above. Check `pg_policies` and
`information_schema.role_table_grants` directly against the live database
first - if both are clean, the bug is very likely a client-side
resilience gap (an eager/memoized fetch racing session restore, or a
call site missing the fail-soft handling a sibling call site already has
for the same known burst-timeout), not an RLS regression. Don't
re-investigate the RLS hypothesis a second time on this table without
first re-running these exact checks.


## InnoVint publishes an OpenAPI spec - it IS discoverable

`contracts.py` claimed for months that "InnoVint's own API docs for this
resource set were not discoverable," and every contract was transcribed from
observed responses instead. That claim was wrong. Three endpoints serve
documentation to the ordinary access token:

- `GET /api/v1/schema` - full OpenAPI 3.1 YAML, ~350KB, 60 documented paths
- `GET /api/v1/docs` - rendered docs UI
- `GET /openapi.json` - a separate "MAKE Internal APIs" spec

This had a real cost. An investigation into fruit intake data concluded no
harvest resource existed, having probed ten guessed LOT-scoped paths
(`/lots/{id}/harvests`, `/intakes`, `/weighTags`, ...) which all 404. The
real resources are WINERY-scoped - `/wineries/{id}/actions/receiveFruitActions`
and `/wineries/{id}/growerReceipts/{vintage}` - and are both plainly listed
in the spec. The wrong conclusion ("InnoVint's fruit data is structurally
fake") survived for months on the strength of guessed endpoint names.

RULE: check `/api/v1/schema` before concluding a resource doesn't exist, and
derive new contracts from the spec's declared nullability rather than from
observed samples. Sample-derived nullability is weak evidence - all 6
growerReceipts rows have every field populated, which says nothing about
whether any field CAN be null.

## harvest_receipts reconciles deletions; lot_analyses/vessels don't

A deliberate divergence between sibling ingestion paths, recorded so the
inconsistency isn't read later as an oversight.

`upsert_lot_analyses`/`upsert_vessels` are pure `on conflict do update`, with
no delete anywhere in `db.py`. That is correct for them: their sources expose
`deleted`/`archived` flags, so a removed record still arrives as data.

`/growerReceipts` exposes NEITHER a `deleted` field nor a `state` filter -
unlike `/actions/receiveFruitActions`, which has `ACTIVE`/`DELETED`/`EDITED`.
A deleted receipt simply vanishes from the response. Pure upsert would leave
a phantom harvest in a panel that claims to be real, with no error - so
`upsert_harvest_receipts` reconciles the full per-vintage payload instead.

The scoping is the entire safety of this, per the Track 2 irrigation scoping
mistake above: the delete is bounded to `source_system='innovint'` AND the
specific vintages fetched that run. Two properties make it safe, and both
must survive any refactor: (1) every fetch completes before any write, so a
failed fetch raises with nothing deleted; (2) the vintage list is passed
explicitly rather than derived from the fetched rows, so a vintage that
legitimately returned zero receipts is still reconciled - while an empty
response from a broken run never reaches the delete at all.

RULE: never widen this delete's scope to "all innovint rows" or derive its
vintage list from the payload. An empty API response must never be
interpretable as "delete everything."

## The winery vintage/block filter bar was written but never wired - real fruit data was unreachable through the UI

`renderFilters()` had a complete, correctly-written `tab==='winery'` branch
from the moment it was authored - its own meta text even said "Vintage
scopes fermentation and harvest panels only," describing behavior for a
control that didn't exist yet. Two things were missing:

1. No host element. `web/index.html` only ever had `<div class="filters"
   id="f-vineyard">` - there was no `#f-winery` for the branch to render
   into.
2. No call site. `renderTab()` called `renderFilters(tab)` only `if(tab===
   'vineyard')`.

The result: `state.winery.vintages` was permanently pinned to `[CURRENT]`,
with no UI path to ever change it. Every piece of real InnoVint fruit
intake work in this project - `harvest_receipts`, `REAL_FRUIT_VINTAGES`,
the real/mock branch in `renderFruit()` - was correctly built and correctly
verified at the database and Node level, and was STILL completely
unreachable by an actual user, because nothing in the UI could ever select
2022, 2023, or 2024 on the winery tab. This was found by an
approved-operator BROWSER walkthrough, not by code review or any DB/node-
level check - the code read as complete on inspection, since the missing
pieces (a host div, one call-site condition) are easy to overlook as
"obviously must be wired up already" when the function itself is fully
implemented.

**Both tabs render at boot** (`renderTab('vineyard'); renderTab('winery');`,
unconditionally, before either is switched to) - a fact that surfaced two
further, contained bugs while fixing the gap above, both from the same root
cause: code written assuming only one tab's filter bar would ever exist in
the DOM at a time.

- `id="vdd-wrap"` was a single hardcoded id. Adding winery's control would
  have created a duplicate id, and the outside-click-closes handler's
  `$('#vdd-wrap')` returns only the first DOM match - winery's dropdown
  would never have closed on an outside click. Fixed with per-tab ids
  (`vdd-wrap-vineyard` / `vdd-wrap-winery`).
- `vintageDDOpen` was a single shared boolean. Opening one tab's dropdown
  would leave the flag `true` for both, so the other tab's dropdown would
  render pre-opened on its next `renderTab()`. Fixed by keying it per tab.

**The control was then relocated from a page-wide bar into the Harvest
section specifically** (a control strip between the section's `.sect`
header and its `.grid`, not the top-of-tab bar vineyard uses) - vintage was
found to scope exactly one section (`fruit`) plus one panel that lived
outside any section (`anom-w`, the winery insights panel, built directly in
the hero). Moving the control into Harvest while leaving `anom-w`
vintage-scoped would have meant a control that visually lives in one place
still silently driving a panel elsewhere on the page.

Three options were considered for `anom-w`: pin it to `CURRENT` (making the
whole winery hero uniformly live, matching `paintOverviewW` and both cellar
panels, which were already `CURRENT`-only); leave it vintage-scoped but add
a visible "Vintage: X" indicator to the panel; or don't move the control at
all, since a page-wide control was an accurate representation of its true
reach. **Pinning to `CURRENT` was chosen** (Option A) -
`anomCtx={...c, primary:CURRENT, vintages:[CURRENT], compare:false,
align:false}` passed into `renderAnomalies`, blocks left live from `c`.

**Recorded plainly as a deliberate capability removal, not a side effect:**
winery insights no longer reflect a selected historical vintage. Before
this, a user could ask "what would the rules have said in 2023?" by
selecting that vintage; after, `anom-w` always describes `CURRENT`
regardless of what's selected in Harvest. This was a real tradeoff, decided
in favor of not leaving one page-wide-looking control with one
section-scoped and one hero-scoped effect.

RULE: a written-but-unwired UI branch - real code, with no host element and
no call site - passes code review easily, because the branch itself looks
complete. It only surfaces by actually using the feature end to end. This
is the first of two instances in this project where a browser pass found
something no amount of DB- or Node-level verification could have (the
second: the `renderTab()` entry directly below).

## renderTab()'s returned promise resolved before panels actually finished rendering - broke a scroll-restore fix silently

Found while verifying the winery filter bar relocation above: selecting a
new vintage in the Harvest strip made the page visibly jump to the top and
stay there - discovered only by actually scrolling partway down, clicking a
vintage, and watching, not by reading the code, which looked correct.

The scroll-restore code read `const sy=window.scrollY;
renderTab(tab).then(()=>requestAnimationFrame(()=>window.scrollTo(0,sy)));`
- reasonable-looking, and wrong, because `renderTab()`'s own last line was
`requestAnimationFrame(()=>{ pending.forEach(f=>f()); });` - fire-and-
forget. The `async function renderTab`'s promise resolves right after
SCHEDULING that frame, not after any panel actually finishes rendering. So
`.then()` fired almost immediately, while the DOM was still just-rebuilt
skeletons (`docH` ~1000px) - `window.scrollTo(0,sy)` got silently clamped to
0 by the browser (nothing to scroll to yet), and nothing ever retried once
the page grew back to its real height over the following several seconds of
async panel fetches. Confirmed via instrumentation, not a visual glance:
wrapping `window.scrollTo` to log every call's arguments,
`document.body.scrollHeight` at call time, and a sampled timeline showed
exactly this - one clamped call at `docH=1093`, then `docH` climbing to
2162 with `scrollY` stuck at 0 for the next six seconds.

**Fix, in `renderTab()` itself:** replaced the fire-and-forget
`requestAnimationFrame` dispatch with `await new
Promise(res=>requestAnimationFrame(res)); await
Promise.allSettled(pending.map(f=>f()));`. Same rAF timing as before
(panels still start only after one layout tick, preserving the existing
"render bodies after layout so clientWidth is correct" behavior) - the only
change is that `renderTab()`'s promise now waits for every panel to finish
before resolving.

**Blast-radius check performed before taking this, not assumed safe:**
every one of the 12 `renderTab(...)` call sites in the file (map block
toggle, ferm lot select, vessels-archived toggle, block chip clicks, range
button clicks, both history scroll buttons, tab switch, window resize, and
the two boot calls) is a bare fire-and-forget statement - none `.then()`s
or `await`s the result, and none has code after the call that assumed
fast/synchronous completion. The scroll-restore code was the only caller
anywhere that observed the promise at all, so widening what "resolved"
means could not break an existing caller.

**Incidental fix included:** two `pending` entries (`()=>paintOverviewV(...)`,
`()=>paintOverviewW()`) are pushed raw, outside `makePanel`'s internal
try/catch - a throw in either previously became a silent
unhandled-promise-rejection console warning. `Promise.allSettled` (chosen
over `Promise.all`) absorbs that for free, without changing any
user-visible behavior.

Re-verified with the same instrumentation after the fix, not just a visual
check: `scrollTo()` now fires only once `docH` has reached its final
settled value, and `scrollY` lands exactly on the saved position and
holds. (One trial correctly did NOT restore to the saved value - a
transition into the much-shorter 2026 "no fruit yet" mock page, where the
browser's own clamp to the new shorter max is the correct behavior, not a
failure.)

RULE: when a promise-returning function is called fire-and-forget
everywhere except one new caller that needs to `await` it, check whether
the function actually resolves at the moment callers would assume it
does - don't take "it returns a promise" as proof it resolves at the
semantically correct time. This is the second of two instances in this
project where only an actual browser pass (not a DB or Node-level check)
could have found the bug - the first: the winery filter bar entry directly
above.


## DTR threshold (dtr_low, 21°F) investigated and confirmed correct - no change made

Tracked item B's DTR half. Real empirical distribution, `daily_derived.dtr_f`,
857-860 real days (2022-2025, growing season): p10=20.8, p25=26.7, p50=31-32,
p75=35.7, max=47.2°F. `dtr_low` (`operator='lt'`, `threshold=21`,
`severity='note'`) sits close to the real p10, and the current trigger rate
(~10-12% of real days) is a coherent design for a "note"-severity anomaly -
occasional, not constant, not unreachable.

Two wine-trade literature leads found this session would have argued for
raising the threshold dramatically: a Howell-Mountain-specific claim of
diurnal swings "commonly exceeding 50°F," and a Paso Robles Cabernet
Sauvignon citation at 35-50°F. Both were checked directly against this
site's own real data, not adopted on the strength of sounding specific -
the single highest DTR ever recorded across 4 full real seasons is 47.2°F,
once. Neither claim is corroborated here; both read as overstatements once
checked against real measurements, not something to import as a new
threshold.

RULE: a wine-trade or content-site claim about a specific site's climate is
not a substitute for that site's own real data, even when the claim is
worded specifically and confidently. Check it against real measurements
before treating it as evidence for a threshold change - the same discipline
already applied to GDD/DTR's own Napa Valley Grapegrowers calibration, now
applied in the opposite direction (rejecting a lead, not adopting one).

## VPD: the metric itself was wrong, not just the threshold - new vpd_peak_kpa column, new two-tier thresholds, old rule disabled

Tracked item B's VPD half, closing it out. The original threshold
(`vpd_high`, `metric_key='vpd'`, `operator='gt'`, `threshold=3.1`,
`severity='warn'`) was compared against `daily_derived.vpd_kpa`, which is
computed from `tavg_f`/`rh_avg` - already-daily-averaged inputs.
Structurally, no daily-average quantity can represent an afternoon peak:
confirmed directly against the real column, the highest `vpd_kpa` ever
observed across 4 real seasons is 3.64 kPa, crossing the 3.1 threshold on
just 0.8% of days - de facto almost unreachable, regardless of what any
literature said the "right" number should be.

**New literature found this session was genuinely stronger than the
original investigation's, and worth taking seriously - but not at face
value against the wrong quantity.** A peer-reviewed OENO One review citing
a real Napa field study (Scholasch et al. 2009) reports maximum afternoon
VPD reaching 6.5 kPa; an independent primary-source sap-flow paper by the
same researcher reports 6.6 kPa; a 20-year CIMIS-station analysis from a
neighboring North Coast AVA confirms summer afternoons commonly reach 6-7+
kPa. All three are genuinely field/viticulture-specific and North-Coast-CA
relevant - unlike the generic greenhouse-crop literature the original
investigation found. Comparing this literature against `vpd_kpa` directly
would have wrongly suggested it overstates real conditions here by roughly
2x. That would have been a methodology artifact - comparing a peak-condition
citation against a daily-average number - not a real difference between
this site and the literature.

**Fix: a genuine peak-hour VPD, computed independently and added as a real
column, not a threshold tweak.** `daily_weather.vpd_peak_kpa` is now
computed by the `daily_weather.sql` dbt model itself, from real hourly
`air_temp`+`humidity` (`sensor_readings`, 5,136 rows/vintage, confirmed
genuinely hourly) - paired per hour, run through the same Tetens formula
`daily_derived.vpd_kpa` already uses, then reduced to the day's max.
Deliberately placed as a `daily_weather` dbt column, not a `daily_derived`
view-time subquery against `sensor_readings`: `daily_derived` is read
frequently, including by `anomalies_eval()`'s hot-path "just the latest
row" query (`order by day desc limit 1`), which Postgres can push down
efficiently through a simple view - an expensive per-row hourly
aggregation inside the view would very likely defeat that pushdown,
forcing a full-season aggregation just to read one row. `daily_derived`
now just passes `vpd_peak_kpa` through unchanged, at the same near-zero
cost as its existing `dtr_f` pass-through.

**New `metric_key='vpd_peak'`, not a redefinition of `'vpd'` in place.**
Traced every consumer of the literal string `'vpd'` before deciding this
was safe: `anomalies_eval()`'s own `derived_unpivot` CTE (the one place
that matters), an orphaned dbt model
(`ingestion/mars_dbt/models/curated/anomalies.sql`, dead - see below), and
two unrelated namespaces (`web/index.html`'s panel id `'vpd'`, and the
chat tool's raw `vpd_kpa` column reference). Redefining `'vpd'` in place
would have silently changed what the *existing*, still-`enabled=true`
`vpd_high` row compared its untouched 3.1 threshold against - its observed
rate would have jumped from 0.8% of days to roughly 43%, with nothing
anywhere signaling the row's meaning had changed.

RULE: before adding a second meaning to an existing identifier, trace
every consumer of the literal string first. This is the same reasoning
that chose `block_innovint_map`'s time-scoped extension over redefining
`blocks.innovint_block_id` in place - a new, explicit thing alongside the
old one, not a silent reinterpretation of what the old one already means.

**Two-tier design, matching an existing precedent in this table.**
`vpd_peak_warn` (`gt 5.0`, `warn`) and `vpd_peak_alert` (`gt 6.5`,
`alert`), both `metric_key='vpd_peak'`. 6.5 is anchored directly to the
corroborated literature ceiling (both Scholasch-researcher sources cite
6.5-6.6 kPa almost identically); 5.0 is anchored to the real p90-p95 band
of the corrected peak-hour distribution (see below). Two tiers, not one,
for the same reason the winery's hot/warm fermentation-temperature pair
already uses two: one physical quantity, two severities, matching
precedent already in this table rather than inventing a new idiom.

**Old `vpd_high` disabled, not deleted.** `enabled=false` is an
established pattern in this exact table, not a new mechanism -
`air_temp_high` already sits disabled today while every other row
(including mock-backed ones) stays enabled. Verified live against a real
date, not just reasoned about: 2024-07-06 (`vpd_peak_kpa=8.38`, the season
max; the *old* average-based `vpd_kpa=3.44` on the same day - itself above
the old 3.1 threshold too). `anomalies_eval(2024, '2024-07-06T02:00:00Z',
'vineyard')` returned both new rules firing correctly, and `vpd_high`
absent from the results despite its own condition being genuinely true
that day - proving the disable is respected, not just coincidentally
inert on dates that happen not to need it.

**The `vpd_low=0.4` hardcoded display band was also wrong, and inert -
never a live DB threshold at all.** Corrected to 0.16 kPa (the real median
daily-minimum VPD, computed the same way as the peak). Found only by
checking whether the JS-side fix was actually visible after applying it,
not by assuming a corrected fallback value takes effect: `vpd_high`'s own
`display_label` column stored `'Productive band 0.4-{threshold} kPa'` with
the wrong "0.4" baked in as **literal text**, not a `{threshold_low}`
template placeholder - `interpolateThreshold()` only substitutes
`{threshold}`/`{threshold_low}`/`{threshold_high}`, so the stored literal
overrode the corrected JS fallback in the actual chart legend regardless
of the JS fix. `getThresholds()` fetches all rows with no `enabled`
filter, so disabling `vpd_high` for anomaly-firing purposes did not fix
this either - it needed its own correction, applied in the same migration
since it's the same row.

RULE: after fixing a displayed value, verify the fix is actually visible
end-to-end, not just that the code path you edited is correct in
isolation. A second, DB-stored copy of the same wrong number can silently
override a corrected JS fallback - this was only caught by checking, not
by trusting that changing one `const lo = ...` line was sufficient.

**Recurred once already, on a different row - see the
`soil_below_refill` entry below.** `display_label` holding a literal
hardcoded number instead of a `{threshold}` placeholder is not a
one-off gap specific to `vpd_high`; treat it as a standing property of
this table. Whenever a `threshold` value changes on ANY row, check that
row's `display_label`/`tooltip_phrase`/`message`/`action_line` for a
literal hardcoded number before considering the fix complete - don't
assume only the row a prior incident already flagged is affected.

**Two real bugs caught during implementation, not glossed over.**

1. An ambiguous column reference (`vintage`/`day`, present in both the
   `hourly` and new `daily_vpd_peak` CTEs after the `LEFT JOIN`) that
   `dbt compile` could not catch - compile is Jinja templating only, not a
   live query plan, and only surfaced when the actual
   `dbt run --full-refresh` executed against the real database. RULE: a
   clean `dbt compile` is not proof a model works; only a real run against
   real data is.
2. The investigation's own ad-hoc percentile computation (this session,
   before the dbt column existed) used UTC-date bucketing
   (`recorded_at::date`) rather than Pacific-local bucketing - the exact
   same bug already documented and fixed once for `tmax_f`/`tmin_f`/
   `dtr_f`, now found a **second** time, in independent analysis code
   rather than the pipeline itself. Corrected mean: 2.86 kPa, vs. the
   original flawed 2.96. Percentiles from p90 up shifted by ≤0.03 kPa only
   - the upper-tail extremes that actually matter for a threshold are
   driven by mid-afternoon hours, nowhere near a day boundary, so they're
   largely insensitive to a bug that reassigns evening hours across
   midnight and meaningfully moves the mean. Re-verified crossing
   fractions directly against the corrected, live column before
   confirming the thresholds still held - 5.0 crosses on 8.1% of real
   days, 6.5 on 1.52% (~3/season) - both still matching original design
   intent almost exactly. Confirmed, not assumed: this was checked with a
   real query after the correction, not inferred from how small the mean
   shift looked.

**The disruptive dbt full-refresh step reproduces the same documented
hazard as every prior `daily_weather` full-refresh, not a new one** - see
the existing "dbt full-refresh on an incremental model drops dependent
views AND their grants, silently" entry above. `daily_derived` and its
grant were cascade-dropped exactly as that entry predicts; both were
restored and independently re-verified via `information_schema`, then
adversarially re-tested as `role authenticated` (not superuser) before
being trusted.

**Flagged, not fixed:**
- `ingestion/mars_dbt/models/curated/anomalies.sql` - an orphaned dbt
  model duplicating `anomalies_eval()`'s logic, with no `ref()` consumer
  and no schedule (confirmed dead, not assumed). It has no `vpd_peak`
  branch and will drift further out of sync now that one exists elsewhere.
- `supabase/functions/chat/tools.ts` - `get_derived_series`'s tool
  description text and its `.select(...)` column list both still name
  only the original four derived fields (`gdd_cumulative`, `dtr_f`,
  `vpd_kpa`, `et0_in`). Needs `vpd_peak_kpa` added whenever this tool is
  next touched, or the chat can't be asked about peak-hour VPD at all.


## Soil moisture threshold (soil_below_refill, 15% -> 13.8%) corrected after the same real-data check DTR/VPD got - tracked item E closed

Tracked item E, closing it out. `soil_below_refill` (`metric_key=
'soil_moisture'`, `operator='lt'`, `severity='alert'`) was evaluated
directly against real `sensor_readings` (not a `daily_derived`
aggregate - soil moisture never went through the derived-metric layer
the way DTR/VPD did). Real distribution, 20,544 real hourly readings
(2022-2025, ERA5-Land, estate-level): p05=13.8, p10=13.8, p25=13.9,
p50=14.7, p90=28.9, p95=33.2, max=43.5.

**At the old threshold (15), 52.4% of ALL real readings crossed it** -
not a rare alert condition, effectively always-on. A monthly breakdown
(2023) shows why: the soil drains steadily April-June, then sits on a
stable near-floor plateau (monthly average 13.9-14.1%) for the entire
July-September ripening season, every real year - it doesn't fluctuate
or worsen, it settles there and stays. An alert that fires continuously
for three straight months, every season, on a completely normal and
unchanging condition gives an operator no discriminating signal at all.

**The loam-vs-rocky-loam cross-check, resolved by real data rather than
a choice between citations.** Aiken (Howell Mountain's dominant series)
is officially mapped as "loam" texture in USDA/NRCS survey data, and a
generic texture-class reference (Cornell CALS) gives loam field capacity
as roughly 35-45% VWC - taken at face value, that would suggest the
current threshold undershoots badly. But many of Aiken's real NRCS map
units are specifically cobbly/stony/very-rocky variants, and rock
fragments hold essentially no plant-available water, reducing a soil's
*effective* water-holding capacity well below what its fine-earth
texture class alone implies. The real observed summer floor
(13.7-14.1%) sits below even a generic "sandy" assumption (15-25%), let
alone unmodified loam - this **corroborates the rock-fragment reasoning
more strongly than expected**, confirmed directly against real
measurements, not decided by picking which literature source to trust.

**13.8 was chosen deliberately, not as "somewhere lower than 15."**
Crossing rate at a few candidate values: 13.8 -> 0.73%, 14.0 -> 29.78%,
14.5 -> 46.04%, 15.0 (old) -> 52.40%. There's a steep cliff between 13.8
and 14.0 - the plateau's own noise floor sits almost exactly in that
gap, so any value placed inside it would be highly sensitive to exactly
where the real floor lands in a given season. 13.8 sits at the clean,
defensible edge of the real plateau (matching p05/p10 almost exactly)
rather than inside the noisy transition zone, restoring genuine rarity
(0.73%, comparable to VPD's alert tier at 1.52%) instead of landing on
an arbitrary point that happens to be lower than the old number.

**The same `display_label` literal-text bug found on `vpd_high` showed
up again here** - `display_label` stored `'Target 15-25 % VWC'` as
literal digits, not `{threshold}`/`{threshold_low}`/`{threshold_high}`
placeholders. `tooltip_phrase` was already correctly templated
(`'under the {threshold}% VWC floor...'`) and needed no change - checked
directly, not assumed clean just because one field on the row was fine.
Corrected in the same migration to `'Target 13.8-29 % VWC'`. See the
RULE extension on the VPD entry above - this is now confirmed to recur,
not a one-off.

**The upper display bound (25 -> 29) was also corrected, anchored to
real p90 (28.9) - but this is a related, not identical, situation to
`vpd_low`'s earlier fix, and shouldn't be read as a clean repeat of that
reasoning.** No `soil_above_target` row exists in `anomaly_thresholds` -
`hi=25` was always a JS-only display fallback, never a live threshold.
Checked against real data: 25 sits below real p90 (28.9) and well below
p95 (33.2) - 10%+ of real readings exceed it. The nuance `vpd_low`
didn't have: this panel's own info text frames the band as *"the
deficit-irrigation target, deliberately kept below field capacity... not
a sign of stress unless it drops well under the band"* - a management
target, not a claim about the full observed range. Part of why real data
exceeds 25 is structural, not just a stale number: April alone averages
30.1% VWC (the normal pre-deficit-management spring wet season, before
deficit irrigation is even in effect), not an anomaly. The p90 anchor is
still the right fix for what the chart visually communicates to a
viewer who can't otherwise tell "expected spring wetness" from
"unusually wet summer" - but it's flagged here as a distinct situation
with its own reasoning, not vpd_low's fix reapplied verbatim.

**`scope_level='block'` on this row is decorative, not functional -
confirmed by reading `anomalies_eval()`'s live function body directly,
not assumed.** The row's `scope_level` column is never referenced
anywhere in the function's actual join/filter logic - it evaluates
purely on `metric_key` matching against `latest_sensor`'s real data,
which is estate-level only (`block_id` always null for real soil
readings; ERA5-Land's grid can't resolve the three blocks). Verified
live against a real date (2023-07-15): the rule fires correctly with
`block_id=null`, matching the labeled scope's own reality. Worth a note
specifically because `scope_level='block'` could otherwise mislead a
future reader into believing this project has, or is building toward,
per-block soil moisture alerting - it doesn't, and the column value
doesn't reflect anything that's actually wired up.

**Estate-level-only caveat, same shape as DTR/VPD's.** ERA5-Land's grid
can't distinguish this estate's three blocks, standing in for a
property with genuinely different plantings and ages (B1's young
replanted vines vs. B2/B3's established ones). This changes confidence
in the *exact* value, not the *direction* of the finding: the shape (a
stable summer plateau sitting well below the old alert floor, every real
year) is a property of the whole-estate curve relative to the
threshold, and wouldn't flip if block-level data existed. Treat "the old
threshold was miscalibrated to near-permanently-on" as solid; treat
13.8 specifically (versus some other point at the edge of the same
plateau) as reasonable but not beyond revision if block-level real data
ever becomes available.

## sensor_read RLS policy: the named suspect was only ~15% of a 2-6s cost - current_role_name() being called per row was the rest

A performance audit measured `anomalies_eval()` at 2-6s end-to-end for a
real authenticated operator (REST, RLS engaged) - traced via `EXPLAIN
ANALYZE` run as `role authenticated` (not superuser-bypassed) to
`sensor_read`'s `latest_sensor` `DISTINCT ON` subquery: 843ms in-DB vs
264ms bypassing RLS entirely, with a `metric_registry` lookup showing
`loops=17656` in the plan - a correlated scalar subquery
(`(select m.min_role from metric_registry m where m.metric_key =
sensor_readings.metric_key) = 'all'`) re-executed once per candidate row
instead of once.

**The initial hypothesis, fixed first, was correct but incomplete - and
that gap was found by isolating, not by stopping at the first
improvement.** Rewriting the `metric_registry` check as a non-correlated
`IN` (`metric_key in (select metric_key from metric_registry where
min_role = 'all')`, safe because `sensor_readings.metric_key` has a NOT
NULL FK to `metric_registry.metric_key` - every row has exactly one
matching row, no NULL-handling divergence between the two forms) dropped
`loops` from 17,656 to 1, but only moved the query from 843ms to 729ms -
a real but small ~15% of the total. A diagnostic run (real policy logic,
not a shortcut: `metric_registry` fixed, `current_role_name()` calls left
real) measured 712ms **with the metric_registry cost entirely absent** -
proving the dominant cost was somewhere else, not what the correlated-
subquery evidence had pointed at.

**The dominant cost: `current_role_name()`, a zero-argument `STABLE` SQL
function, was being invoked as a per-row `FuncExpr` rather than hoisted
into a single-evaluation `InitPlan`.** Confirmed by isolating it the same
way - a diagnostic with `metric_registry` fixed and every
`current_role_name()` call replaced by a literal `true` dropped execution
to 32.5ms, and a second diagnostic keeping one real `current_role_name()`
call (no `metric_registry` involvement at all) reproduced almost the
entire original cost on its own (711.7ms). Fix: wrap the call as a scalar
subquery, `(select current_role_name())` - the same idiomatic pattern
Supabase's own RLS performance guidance recommends for `auth.uid()` in
policies, applied here to a locally-defined `STABLE` function of the
identical shape (zero arguments, depends only on session-scoped state).
Postgres treats a non-correlated scalar subquery as an `InitPlan` -
evaluated once, cached, reused for every row - where it does not
extend that treatment to a bare function call in a filter expression,
even a zero-argument `STABLE` one.

RULE: when a diagnosed root cause only partially fixes a measured
problem, isolate further rather than accepting the partial win as the
full answer. This is the same discipline already on record for the VPD
investigation above (two independent bugs found by not stopping after
the first one explained *some* of the gap) - now applied to a security-
relevant RLS fix, where getting the actual cause right matters more, not
less, than for a threshold or subtitle.

**Combined fix, both rewrites together:**

```sql
create policy sensor_read on sensor_readings for select using (
  (
    (
      metric_key in (select metric_key from metric_registry where min_role = 'all')
      and (select current_role_name()) in ('operator','customer')
    )
    or (select current_role_name()) = 'operator'
  )
  and (block_id is null or block_id in (select accessible_blocks()))
);
```

**Behavioral equivalence, proven at the row-set level, not row counts -
and re-proven against the live policy, not just a pre-apply test.** A
security policy rewrite needs stronger proof than "returns about the same
number of rows": full ordered-row-set MD5 checksums
(`md5(string_agg(t::text, '|' order by metric_key, block_id, tank_id,
recorded_at)))` were computed for the exact same query under the old
policy and the candidate policy, for two real roles - an unrestricted
operator (40,527 rows) and a genuinely block-scoped customer (a real
`customer_block_access` row granting only B2, 35,952 rows). Both
checksums matched exactly, first in a rolled-back transaction before
proposing the change, and **again after the policy actually went live** -
the same checksums, computed fresh against real current data, not
recalled from the pre-apply run. `anomalies_eval()` itself was checked the
same way: identical `rule_key`/`observed_value` output before and after,
both pre-apply and post-apply.

RULE: a security policy rewrite needs row-set-level equivalence proof
(a full checksum of what each role can see), not row counts alone - a
row count can match by coincidence while the actual visible rows differ.
And that proof needs re-running against the live state after the change
ships, not just trusted from a pre-apply rolled-back-transaction test -
the mechanism is the same, but "verified in a transaction that never
committed" and "verified against what real traffic now sees" are not
interchangeable claims.

**Real measured impact, both roles, in the numbers that actually answer
"does this feel faster" - not just an in-DB EXPLAIN figure:**

- `anomalies_eval()` REST latency, vineyard test date (2024-07-06):
  2.96-5.96s -> **0.44-0.92s**.
- `anomalies_eval()` REST latency, winery test date (2026-08-30):
  1.99-2.11s -> **1.28-1.64s**. Real and worth having, but plainly a
  smaller improvement than vineyard's - not stated as if both tabs
  improved equally, because they didn't.
- Full cold-load wall clock, both tabs, Playwright, throwaway operator
  account: ~20.0-20.7s -> **~5.1-5.3s**, two trials each side.
- The `57014 canceling statement due to statement timeout` errors already
  documented above (the "anomaly_thresholds permission denied" entry's
  burst-timeout finding) appeared on every pre-fix cold-load trial and
  were **absent from both post-fix trials** - independent corroboration
  from a different signal that the real root cause was fixed, not just
  one symptom of it.

**Winery's smaller improvement is flagged, not resolved.** Vineyard and
winery both call the same `anomalies_eval()` function, went through the
same fix, and were measured the same way - yet winery only improved
~1.3-1.6x while vineyard improved ~5-7x. This suggests a separate,
still-uninvestigated latency source specific to the winery path (a
different table's RLS cost, a different query shape, different data
volume at that test date) rather than the same bottleneck this entry
fixes. Not investigated further here - a candidate for future
investigation, not something this fix was expected to also resolve.

## daily_weather (vintage, day) index - ascending, not matching the hot-path query's own ORDER BY DESC

`daily_weather` had no index of any kind (confirmed via `\d
daily_weather` - no PK, no secondary index), despite dbt's incremental
config declaring `unique_key=['vintage','day']` - that's a dbt upsert key,
not a DB constraint, and never created one. `anomalies_eval()`'s hot path
reads through `daily_derived` (a plain view) with `where vintage =
p_vintage and day <= p_as_of order by day desc limit 1`, which was doing
a Seq Scan on `daily_weather` - cheap only because the table is currently
tiny (979 rows), a growing-table regression risk left as-is.

**Tested both directions in rolled-back transactions before picking one,
rather than assuming the query's own `ORDER BY day DESC` meant a
descending index would obviously win.** It didn't: `(vintage, day desc)`
measured 7.03ms (an "Index Scan Backward"), `(vintage, day)` ascending
measured 3.28ms, index-scan step alone 0.44ms vs 4.2ms. The reason:
`daily_derived.gdd_cumulative` is a window aggregate (`sum(gdd_day) over
(partition by vintage order by day)`), which needs `day` ascending per
vintage to compute correctly - that requirement, shared by every reader
of the view, matters more than superficially matching the `ORDER BY ...
DESC` of one particular caller's final `LIMIT 1`.

Applied: `create index daily_weather_vintage_day_idx on daily_weather
(vintage, day);`. Live result on the real hot-path query: 9.7ms -> 3.6ms,
now an `Index Scan` instead of a `Seq Scan`.

## Logo (LOGO_SRC): lossless recompression, not palette reduction - the image has a genuine alpha gradient, not flat art

The inline base64 logo was flagged as oversized during the same
performance audit: a 151x180px PNG decoding to 53,841 bytes, ~25% of
`web/index.html`'s entire raw byte size on its own. Checked the actual
encoding before assuming any fix, not just the byte count: 8-bit RGBA
(color type 6), 3,230 unique colors, and a **full 256-value alpha
gradient** (genuine soft edges/anti-aliasing, not a flat-color mark).
That last fact ruled out palette reduction (color type 3, which caps at
256 total colors) as a same-quality option - with 3,230 real colors,
quantizing down would need dithering and could visibly band the gradient.
Lossless recompression was chosen instead: `zopflipng`'s more exhaustive
DEFLATE/filter search, same pixels, better encoding only.

Result: 53,841 -> 32,726 bytes (39.2% smaller). **Verified pixel-identical,
not just "looks the same"**: `PIL.ImageChops.difference(original,
recompressed).getbbox()` returned `None` - zero differing pixels
anywhere. Checked twice, not once: first against the standalone
recompressed file, then a second time by decoding the base64 straight out
of the actually-edited live `web/index.html`, confirming the bytes that
shipped are the same ones verified, not a temp copy that happened to
match. `web/index.html`: 282,821 -> 254,669 bytes raw, 123,176 -> 101,654
bytes gzipped.

## harvest_lots dropped - source_system='innovint' was a red herring, not evidence

`harvest_lots` (24 rows) carried `source_system='innovint'` on every row,
which read like real data - but a later migration's own comment
(`20260811215238_lot_analyses_vessels.sql`) called it one of "the mock
tanks/harvest_lots tables" being replaced by `lot_analyses`/`vessels`.
These two signals were in direct conflict and neither was trusted on its
own.

**Resolved conclusively by checking row contents, not the provenance
column.** History: created in the very first schema migration
(`20260805221617_core_schema.sql`), alongside `tanks` - both original
mock schema, before any real InnoVint ingestion existed in this project.
Content: all 24 rows form an exact 6-tank x 4-vintage (2022-2025) grid
with an identical tank -> block -> variety mapping every single year -
real InnoVint data (this project's own `harvest_receipts`/B1-replant
history, documented above) is known to change year over year; this
didn't. The decisive tell: `volume_l` sits **frozen per tank_id across
all four vintages regardless of that year's actual `tons`** (e.g. tank
T-05: 620L in 2022, 2023, 2024, and 2025, while its `tons` value varies
0.98-1.11 across those same years) - a real measured juice volume tracks
yield; a constant that ignores yield is a generator artifact. That exact
constant matches, field for field, `web/index.html`'s live client-side
`TANKS` mock array (`T-05: vol:620`) - `harvest_lots` was generated from,
or in lockstep with, that same mock array. Zero consumers repo-wide
(`web/index.html`, `supabase/functions/`, `ingestion/`, all file types) -
only its own DDL/RLS/grant migrations ever referenced it.

RULE: a `source_system` (or similarly named provenance) column value is
not proof of real data on its own - it can be set by a mock-data
generator as a placeholder label anticipating a future real source, or
simply be wrong. Check the actual row *contents* for signs of being real
vs. synthetic (values that should vary with a real-world outcome but
don't, patterns matching a known mock generator elsewhere in the
codebase) before trusting a label - the same discipline this file already
applies to threshold literals and display strings, now applied to
provenance metadata.

## anomalies_eval(): the winery/vineyard RLS-fix asymmetry traced to a second bug in the same function - latest_sensor re-executed 7 times per call

Follow-up to the `sensor_read` RLS entry above, which left winery's
smaller speedup (~1.3-1.6x vs. vineyard's ~5-7x) explicitly flagged, not
explained. Traced by reading `anomalies_eval()`'s live definition
directly and ruling out the obvious suspect first: the function only
ever touches `sensor_readings`, `daily_derived`/`daily_weather`, and
`anomaly_thresholds`, identically regardless of `p_tab` - no second,
differently-shaped RLS policy on `tanks`/`vessels`/`lot_analyses` is
involved, confirmed by reading the function body, not assumed from the
tab name.

**The real cause: `latest_sensor` (the expensive `DISTINCT ON` CTE) sits
on the inner side of a Nested Loop against `anomaly_thresholds` (7
enabled rules per tab), so Postgres re-executes its entire scan once per
outer row - 7 times per call, not once.** Confirmed via `EXPLAIN
ANALYZE` (`loops=7` on the `Merge Append`/`Unique`/`Incremental Sort`
nodes, cumulative `Buffers` roughly 7x a single execution's). This was
invisible to the RLS investigation because that investigation tested
`latest_sensor` as a standalone query, never through the function's
actual join structure - the same discipline this file's RULE already
names (isolate further rather than stopping at a partial explanation),
now catching a second, structurally different bug in the same function
the first fix touched.

Winery's larger absolute cost comes from the same 7x multiplier landing
on a higher per-execution base cost: at the two tabs' respective test
dates, winery's `sensor_readings` scan touched 40,080 rows per loop vs.
vineyard's 17,656 - a property of *which date* happened to anchor each
tab's test (2026-08-30 is later into a still-accumulating season than
2024-07-06 is into a complete, archived one), not anything structural to
"winery" as a tab.

**Fix: mark `latest_sensor` and `latest_derived_row` `MATERIALIZED`** -
forces single-evaluation, the same "compute once, reuse" idea already
applied to `current_role_name()` in the RLS fix, at a different layer of
the same function.

**Equivalence verified at the full-output level across 7 dates before
proposing this, matching the RLS fix's own rigor - and the dates weren't
allowed to coincidentally all agree for the wrong reason.** The first
four zero-hit dates tried all happened to return empty results on both
sides, which would have been weak evidence on its own (two versions
agreeing that nothing happened isn't proof the doy-boundary logic
behaves identically) - so a fifth date was deliberately sought where a
doy-windowed rule (`frost_risk`, `valid_to_doy=130`) actually breaches:
2024-04-06, real sub-freezing readings (28.1°F) within the window, where
`frost_risk` and `humidity_high` both genuinely fire. All 7 dates -
vineyard multi-hit, winery zero-hit, a mild zero-anomaly day, both sides
of the doy=130 boundary, a different winery date, and the genuine
frost-firing date - produced identical `md5` checksums of the complete
ordered result set (not row counts) between the live function and a
temporary `MATERIALIZED` test variant, re-confirmed a second time
against the now-live function post-apply.

**Measured impact:** vineyard (2024-07-06) 550.9ms -> 151.2ms (3.6x);
winery (2026-08-30) 1,232.0ms -> 242.2ms (5.1x) - closes, and here
reverses, the tab asymmetry. Full cold-load wall clock, both fixes live
together: ~20.0-20.7s (original) -> ~5.1-5.8s (RLS fix alone) ->
**~3.7-3.9s** (both fixes).

**The linked pagination-stall question (see the performance-audit work
above) was tested twice, and the first test's negative result was
correctly not trusted as final.** A synthetic concurrent burst (curl,
background-jobbed) swapping the live winery RPC for a fast materialized
test variant showed no clear reduction in a `lot_analyses` pagination
probe's latency (1,195-2,530ms live vs. 1,963-2,162ms materialized -
indistinguishable, if anything backwards) - reported honestly as
inconclusive rather than discarded, since `curl &` backgrounding doesn't
guarantee the same true-simultaneity a browser's concurrent `fetch()`
calls produce, and the real cold load's 48 requests sit closer to the
project's connection ceiling (30 already open at idle against
`max_connections=60`) than a smaller synthetic burst does. The real
Playwright re-test after this fix actually went live settled it
cleanly: the pagination gap dropped from ~2,054ms (RLS fix alone) to
**~1,198-1,260ms** (both fixes) - residual contention over the isolated
baseline (~300-590ms) down from ~4-7x to ~2.1-4.2x.

RULE: a negative result from a hand-built concurrency test doesn't
settle a question a real browser-driven load could still answer
differently - the synthetic test's own methodological gap (smaller
burst, non-simultaneous dispatch) was flagged at the time specifically
so it wouldn't later be misread as "tested and ruled out."

## Winery Harvest vintage control: full renderTab() rebuild converted to a scoped update - three pieces of UI, not one

The Harvest vintage dropdown previously called `renderTabPreserveScroll('winery')`
like every other winery control, even though by this point only one
panel (`fruit`) genuinely reads the selected vintage for its data -
`state.winery.blocks` had already been made permanently fixed (the
winery block filter was removed entirely) and `anom-w` had already been
pinned to `CURRENT`, so the original "a vintage change can touch more
than one panel" reasoning no longer applied to winery specifically.
Confirmed exhaustively before changing anything, not assumed: read
`renderFerm`/`renderTanks` in full (neither references `ctx.primary`
anywhere), and traced `cellart`/`cellarh`/`ferm`/`tanks`'s `sub:`
functions, which do technically take `c.primary` - `getDataSourceLabel()`
proves the output is vintage-*invariant* for their metric kinds
(`building` has no vintage branch at all; `real` falls straight to a
static string), so those four were a false alarm, not a second consumer.

**What actually needed coordinating turned out to be three separate
pieces of UI, none sharing a single update mechanism - not just "the
panel whose data changed":**

1. **`fruit`'s panel body** - already covered by the existing
   `rerenderPanel('fruit')`, itself already safe against the
   append-only-duplication hazard (`renderFruit` self-clears,
   `box.innerHTML=''`, confirmed by its own pre-existing defensive
   comment anticipating exactly this change before it was written).
2. **`fruit`'s own header** - genuinely vintage-dependent (`unit`
   differs `'tons'` vs. `'tons · °Bx · pH'`; `sub` differs between the
   real-InnoVint line and the mock line), and invisible to
   `rerenderPanel()`: `makePanel()` computes `subText`/`unitText` once
   and bakes them into `hd.innerHTML` at panel-creation time, never
   touched again by a scoped re-render. A new `panelHeaders` registry
   (mirroring the existing `panelRuns` pattern exactly - same
   population site, one line added) exposes each panel's `.p-hd`
   element so this one case can recompute and write `.p-sub`/`.p-unit`
   directly.
3. **The Harvest strip itself** - the vintage dropdown's own rendered
   selection state and the "as of `date` `vintage`" / "`vintage`:
   `character`" meta lines are built once per full `renderTab()` by
   `buildVintageGroup()`/`buildVintageMeta()`, entirely outside the
   `makePanel`/`panelRuns`/`SCOPED_RERENDER_SAFE` panel machinery - not
   panels at all. Given an `id` (`#harvest-vintage-strip`) so a scoped
   update can find and rebuild just that one small `<div>` in place.

**Mechanism mismatch confirmed, not assumed compatible.**
`SCOPED_RERENDER_SAFE` is consulted only inside `makePanel`'s
range-button/history-scroll handlers - `buildVintageGroup`'s vintage
`onclick` is a wholly separate code path with its own hardcoded call,
and adding `'fruit'` to that set would have done nothing here. Left
untouched; the vintage handler now branches on `tab` directly instead
(winery calls the new `rerenderHarvestVintage()`; every other tab,
including vineyard, still calls `renderTabPreserveScroll` exactly as
before).

**Verified after applying, not just reasoned about.** Clicked through
all five vintages with a real throwaway operator account: unit
badge/subtitle correctly flip exactly at the real/mock boundary
(2024→2025) at every step, dropdown selection and meta lines always
match. `cellart`/`cellarh`/`ferm`/`tanks`'s actual DOM elements were
marked before the sequence and still had the identical references
after all five clicks - direct proof they were never torn down, not an
absence-of-network inference (that check hit an unrelated instrumentation
bug in the test script and was dropped in favor of the stronger DOM-identity
proof). Vineyard's own vintage control re-tested for comparison: still a
full rebuild (58 Supabase calls for one click, the marked panel's DOM
identity does change), and scroll still correctly recovers via the
untouched `renderTabPreserveScroll` path. One early scroll reading
(822 instead of 600 after the final click) turned out to be Playwright's
own click-action auto-scrolling the on-page trigger into view before
firing, not an app bug - the same artifact this project hit twice before
on the map toggle and block chip; a programmatic click bypassing it
showed scroll holding exactly steady.

RULE: a scoped-rerender fix needs every piece of UI that reflects the
changed state enumerated, not just the panel whose data changed. A
control's own displayed selection state and any meta text near it are
part of that surface too, and typically live in code that was never
written to be re-run outside a full tab rebuild - "does the data update"
is a necessary check, not a sufficient one.

**Bug found immediately after shipping the above, in the panel body specifically - `rerenderPanel('fruit')` re-rendered the same frozen vintage every time, regardless of the click.** Reproduced live before investigating: header updated correctly on every click (2022→2023→2024), but the panel body stayed on 2026's boot-time mock content the whole time - correct subtitle, stale data underneath it.

**Root cause, confirmed by reading `makePanel()`, not assumed:** `panelRuns[id]` holds the exact closure `makePanel(p, c)` built at panel-creation time - `run: async ()=>{ await p.render(body, {...c, ...}, unitEl); }` - and `c` there is whatever object was passed in at that call, not a live reference. `ctxFor(tab)` builds a brand-new plain object every time it's invoked; it never updates one already handed out. So `rerenderPanel('fruit')` re-runs `render()` against the *same* `c` object from the last full `renderTab()`, forever, no matter how many times it's called afterward or what `state.winery.vintages` has since become. `rerenderHarvestVintage()`'s own header code was fine because it calls `ctxFor('winery')` itself, fresh, right before using it - the bug was specific to going through `panelRuns`/`rerenderPanel`'s stale closure for the body.

**Why the mechanism is correct for what it was built for, and wrong for this.** `panelRuns`/`rerenderPanel()` exists for two callers, both of which *want* to reuse an already-current context: `POLL_5MIN_PANEL_IDS`'s 5-minute timer (re-running the identical query on a schedule - the context hasn't changed, only time has, and the query itself is what picks up new data) and `SCOPED_RERENDER_SAFE`'s range-button clicks (the `c` closed over is still accurate - only `state.range[p.id]`, read fresh from `state` inside the closure at call time, changed). Neither caller ever needed a *new* `c` - they needed the *same* `c`, re-run. The Harvest vintage control is the opposite case: `state.winery.vintages` genuinely changed, and the whole point of calling anything was to reflect that change - reusing a mechanism built around "the context is still valid" broke exactly where that assumption stopped holding.

**Fix:** `rerenderHarvestVintage()` now rebuilds `panelRuns.fruit` itself, closing over a fresh `ctxFor('winery')`, before calling `rerenderPanel('fruit')` - not just bypassing the stale closure once, but replacing it, so any future caller of `rerenderPanel('fruit')`/`panelRuns.fruit` (e.g. if `fruit` is ever added to `POLL_5MIN_PANEL_IDS` or given a `range:` option) inherits a live context too, not the same landmine. `body` is found via `panelHeaders.fruit.parentElement.querySelector('.p-body')` rather than adding a third registry alongside `panelRuns`/`panelHeaders`, since `hd` and `body` are already siblings under the same panel wrapper.

**Verified against the live, applied code**, not just the design: all 5 vintages clicked with a real throwaway operator account, each showing genuinely distinct, correct data - 2022 (4.802t, 1 lot), 2023 (17.258t, 3 lots), 2024 (16.873t, 2 lots, B1-replant note), 2025 and 2026 (mock branch, correct labels). Scroll preservation and `cellart`/`cellarh`/`ferm`/`tanks` DOM-identity/network isolation re-checked alongside the fix and still hold.

RULE: before reusing an existing "re-render this panel" mechanism for a new trigger, confirm what context it actually captures and when. A mechanism built for "re-run the same thing again" is not automatically safe for "something changed, show the new thing" - those are different contracts that happen to share a function signature.

## service_role has never had table-level GRANTs in this project - BYPASSRLS is not the same gate

Discovered live, by an actual failed run of `insights-scan`, not assumed in advance: `service_role` has NEVER had SELECT/INSERT/UPDATE/DELETE grants on ANY public-schema table in this project. Confirmed via `information_schema.role_table_grants` across sensor_readings, daily_weather, harvest_receipts, vintages, real_data_sources, metric_derivation, and the new insights table: `service_role` has only REFERENCES/TRIGGER/TRUNCATE everywhere (a schema-level default, not per-table grants). `postgres` (table owner) has full access; `service_role` does not inherit it.

The reason this had never surfaced before: neither existing Edge Function ever exercised `ctx.supabaseAdmin.from(table)` directly. `notify-admin-approval` only calls the Auth Admin API (`auth.admin.getUserById()`); `chat` deliberately never uses `ctx.supabaseAdmin` at all, per its own comment ("ctx.supabase is RLS-scoped to the caller's own JWT for every tool call - deliberately never ctx.supabaseAdmin"). `insights-scan` is the first code in this project to read/write arbitrary tables as the service role, and it hit this immediately: `insert into insights` failed with `permission denied for table insights` even though the Edge Function authenticated correctly and `ctx.supabaseAdmin` is genuinely the service-role client.

**This is the two-gates principle above, applied to a role most people assume is exempt from it.** `service_role` does have `BYPASSRLS` - but BYPASSRLS only removes the RLS *policy* gate. It does nothing for the separate table-level *GRANT* gate, the same way a GRANT alone (as documented above for `anomaly_thresholds`) does nothing for the RLS gate. A service-role client with BYPASSRLS and zero GRANTs on a table gets exactly the same `permission denied` a browser-side `authenticated` role would get from a missing GRANT - the failure mode is identical, it just feels more surprising because "service role" sounds like it should mean "unrestricted."

**Fix applied, narrowly scoped, not a blanket fix:** `grant select` on the six source tables `insights-scan` reads, plus `grant select, insert, update` on `insights` itself, to `service_role` specifically. Deliberately NOT `grant ... on all tables in schema public to service_role` / an `ALTER DEFAULT PRIVILEGES` change - that would be a much larger security-posture change made unilaterally, and cuts against this file's own stated philosophy for service-role holes ("each one is a deliberate hole punched through the RLS model... not just 'another function'"). Also note: `daily_derived` has `security_invoker = true` and `series_bucketed()`/`real_metric_vintage_counts()` are plain `language sql stable` (not SECURITY DEFINER) - none of them run with the view/function owner's privileges, so granting only the view/function itself would not have been sufficient; the underlying tables needed the grant directly.

RULE: never assume `service_role` has implicit table access because it has `BYPASSRLS`. Before any new service-role code path goes live, check `information_schema.role_table_grants` for `service_role` on every table it touches, directly - don't infer it from BYPASSRLS, and don't infer it from another function "probably" having needed the same access, since neither existing Edge Function actually exercised this path before `insights-scan`.
