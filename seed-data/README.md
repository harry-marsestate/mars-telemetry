# Mars Telemetry — mock data (v2, matches the mockup's estate model)

Regenerated to match §1 of `mars-telemetry_mockup.html` exactly: Blocks 1–3 (`MRS-1A`–`MRS-3`), 7.3 planted acres, Howell Mountain, **Fahrenheit**, vintages 2022–2026, "now" = **28 July 2026 14:20 PDT**.

All synthetic. The point is that the shapes, units, block IDs, and vintage characters line up with the frontend you already built, so you can wire panels to a real database and have them render correctly before a single real sensor is connected.

---

## Reference tables (small, load as dbt seeds)

| File | Rows | Notes |
|---|---|---|
| `blocks.csv` | 3 | id, label, designation, acres, rows, planted, aspect, elev_ft, color — colors match the mockup |
| `block_lots.csv` | 5 | Variety split per block. B1 is Cab 3.0 / Petit Verdot 0.4 / Cab Franc 0.3 |
| `vintages.csv` | 5 | 2022–2026 with temp offset, water offset, harvest shift, character string |
| `tanks.csv` | 6 | T-01…T-06 with block, variety, volume in litres |
| `metric_registry.csv` | 14 | **Important — see below** |
| `anomaly_thresholds.csv` | 12 | **Important — see below** |
| `work_type_lookup.csv` | 25 | Raw crew-log strings → the 7 canonical operations |
| `users.csv` | 4 | 2 operators, 2 customer accounts |
| `customer_block_access.csv` | 3 | ACCT-01 → B1+B2, ACCT-02 → B3 |

### `metric_registry.csv` — the mockup's `METRICS` object as a table

Columns: `metric_key`, `label`, `unit`, `decimals`, `source_system`, `scope_level`, `min_role`.

`scope_level` is one of `estate` / `block` / `cellar` / `tank` — it tells the frontend whether a metric filters by block. `min_role` is `all` or `operator`, which is what drives panel visibility. Adding a metric later is an insert here plus an ingestion asset — no schema migration, no frontend deploy.

### `anomaly_thresholds.csv` — the mockup's `RULES` array as config

Twelve rules with `severity`, `metric_key`, `operator`, `threshold`, `window_hours`, `title`, `message`. In the mockup these are JS closures in the browser. As rows in a table, the same rules can be evaluated server-side, queried by the chat, and acted on by agents. Tuning a threshold becomes a row update rather than a deploy.

---

## Time series

`sensor_readings_{2022..2026}.csv` — long format, one row per reading:

```
metric_key, sensor_id, block_id, tank_id, recorded_at, value, source_system, vintage
```

| Vintage | Rows | Interval | Coverage |
|---|---|---|---|
| 2022 | 25,924 | 3-hourly | 1 Apr – 31 Oct |
| 2023 | 25,924 | 3-hourly | 1 Apr – 31 Oct |
| 2024 | 25,924 | 3-hourly | 1 Apr – 31 Oct |
| 2025 | 76,036 | hourly | 1 Apr – 31 Oct |
| 2026 | 40,080 | hourly | 1 Apr – 28 Jul (current, in progress) |

Archive vintages are 3-hourly on purpose — enough for 30D and 1Y comparisons, and it keeps the files loadable. 2025 and 2026 are hourly so the 1D and 5D ranges have real resolution.

Metrics present: `air_temp`, `humidity`, `wind_speed`, `wind_dir`, `solar`, `uv` (estate, `WS-01`); `soil_moisture`, `soil_temp` (per block, `SP-01/02/03`); `irrigation_volume` (per block, daily, `FM-01/02/03`); `precipitation` (estate, daily); `cellar_temp`, `cellar_rh` (`CELLAR-A`, year-round); `ferment_temp`, `ferment_brix` (per tank, **only inside each tank's fermentation window**).

`vpd`, `et0`, `gdd`, and `dtr` are deliberately **not** here — they're derived, and they belong in dbt models computed from these readings. Building them is Phase 3 of the tutorial.

---

## Other data

- `work_events.csv` — 717 crew-log rows across 2022–2026: `work_date`, `block_id`, `work_type_raw`, `hours`, `cost_usd`, `crew`, `vintage`. 2026 stops at the current date and mid-season operations are ~48% complete, matching the mockup's `labour()` progress logic. Harvest hours are absent for 2026 — as they should be in July.
- `harvest_lots.csv` — 24 rows (6 tanks × 4 completed vintages) with pick date, tons, Brix, pH, volume. 2026 is empty because it hasn't been picked.
- Two Excel files (separate downloads): `mars-mock-crew-log-2026-clean.xlsx` and `...-messy.xlsx`.

---

## Deliberate edge cases

Planted on purpose. If your pipeline swallows any of these silently, that's a finding.

**Sensor gaps (2026 only)** — real outages you must render as gaps, not interpolate across:
- Block 3 soil probe offline **9 July, 02:00–19:00** (17 hours)
- Entire weather station down **17 June 00:00 – 18 June 11:00** (35 hours)

**Fermentation series are sparse by design.** `ferment_temp` and `ferment_brix` only exist inside each tank's window, which shifts per vintage by `harvest_shift_days` (2023 is +10 days, 2022 is −8). Nothing ferments in 2026 yet. A chart that draws a flat line through the gap is wrong.

**Nullable scoping.** `block_id` is empty for weather-station and cellar readings; `tank_id` is empty for everything except fermentation. Load into staging with these as `text`, cast in dbt — a naive `uuid`/`not null` cast on load will reject perfectly valid rows.

**Soil moisture crosses the 15% refill point** in the dry 2026 vintage, so `soil_below_refill` fires against real data. 2023 (wet, `w=+0.42`) stays comfortably above it. Good for testing that thresholds behave differently across vintages rather than always alerting.

**In `mars-mock-crew-log-2026-messy.xlsx`:** title rows above the real header (row 4); block names typed five ways per block (`Block 1`, `block 1`, `MRS-1A`, `B1`, `Blk 1`); a reference to a nonexistent `Block 4`; missing hours, missing operation, missing date; negative hours (`-4.5`); `312` where a per-person figure belongs; `"8 hrs"` as text; leading/trailing whitespace; one `MM/DD/YYYY` text date among real dates; an exact duplicate row; and a `=SUM()` formula row at the bottom that must not be ingested as data.

---

## Loading

Reference tables → `dbt seed`. Time series → `\copy`, one vintage at a time:

```bash
for y in 2022 2023 2024 2025 2026; do
  psql "$DATABASE_URL" -c "\copy stg_sensor_readings(metric_key,sensor_id,block_id,tank_id,recorded_at,value,source_system,vintage) FROM 'sensor_readings_$y.csv' CSV HEADER"
done
```

Load into a staging table with `block_id text` and `tank_id text`, then cast and constrain in dbt. That's the same path real sensor feeds will take, so it's worth doing properly rather than pre-cleaning the CSVs.

---

## Checks worth running once loaded

1. GDD to 28 July 2026 lands near the mockup's figure — validates the derived-metric model against the frontend's expectation
2. 2023 GDD at the same calendar date is materially lower (cool vintage) — validates vintage offsets survived ingestion
3. Block 3 soil moisture on 9 July returns a **gap**, not an interpolated line
4. `soil_below_refill` fires for 2026 and not for 2023
5. Labour cost per acre, 2026 season to date, across all three blocks
6. Sign in as `buyer@northcoastwine.com` → B3 returns nothing, and `irrigation_volume` / labour cost return nothing on any block
