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
