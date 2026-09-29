// ingest-climate-2026's upsert/refresh window (window.ts).
//   npx deno test --no-lock tests/ingest-climate-window.test.ts
import { assertEquals } from "jsr:@std/assert@1";
import { addDays, lastCompletePacificDay, lastElapsedHourMs, stampUtc } from "../supabase/functions/ingest-climate-2026/window.ts";

Deno.test("cutoff is the top of the current hour", () => {
  assertEquals(lastElapsedHourMs(Date.parse("2026-09-29T13:17:03Z")), Date.parse("2026-09-29T13:00:00Z"));
  assertEquals(lastElapsedHourMs(Date.parse("2026-09-29T13:00:00Z")), Date.parse("2026-09-29T13:00:00Z"));
});

Deno.test("the 2026-09-29 13:17 UTC run would have stored nothing after 06:00 PDT", () => {
  const cutoff = lastElapsedHourMs(Date.parse("2026-09-29T13:17:03Z"));
  assertEquals(Date.parse("2026-09-29T06:00:00-07:00") <= cutoff, true);
  assertEquals(Date.parse("2026-09-29T07:00:00-07:00") <= cutoff, false);
  assertEquals(Date.parse("2026-09-29T23:00:00-07:00") <= cutoff, false);
});

Deno.test("daily refresh stops at the last complete Pacific day", () => {
  assertEquals(lastCompletePacificDay(new Date("2026-09-29T13:17:00Z")), "2026-09-28"); // 06:17 PDT Sep 29
  assertEquals(lastCompletePacificDay(new Date("2026-09-30T03:00:00Z")), "2026-09-28"); // 20:00 PDT Sep 29
  assertEquals(lastCompletePacificDay(new Date("2026-10-01T08:00:00Z")), "2026-09-30"); // 01:00 PDT Oct 1
});

// DST ends 2026-11-01 at 09:00 UTC (02:00 PDT -> 01:00 PST).
Deno.test("cutoff and UTC stamps across the 2026-11-01 DST switch", () => {
  const cutoff = lastElapsedHourMs(Date.parse("2026-11-01T13:17:00Z")); // 05:17 PST
  assertEquals(cutoff, Date.parse("2026-11-01T13:00:00Z"));
  assertEquals(Date.parse(stampUtc("2026-11-01T13:00")) <= cutoff, true);  // 05:00 PST, elapsed
  assertEquals(Date.parse(stampUtc("2026-11-01T14:00")) <= cutoff, false); // 06:00 PST, future
  // What the old scheme would have done with a PST local label: 06:00 PST
  // stamped -07:00 lands an hour early, on 13:00Z, and passes the cutoff.
  assertEquals(Date.parse("2026-11-01T06:00:00-07:00") <= cutoff, true);
  assertEquals(Date.parse("2026-11-01T06:00:00-08:00") <= cutoff, false);
  // Hours either side of the switch stay one hour apart when stamped UTC.
  assertEquals(Date.parse(stampUtc("2026-11-01T09:00")) - Date.parse(stampUtc("2026-11-01T08:00")), 3_600_000);
});

Deno.test("lastCompletePacificDay across the 2026-11-01 DST switch", () => {
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T07:30:00Z")), "2026-10-31"); // 00:30 PDT Nov 1
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T08:30:00Z")), "2026-10-31"); // 01:30 PDT (first)
  assertEquals(lastCompletePacificDay(new Date("2026-11-01T09:30:00Z")), "2026-10-31"); // 01:30 PST (repeated)
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T07:30:00Z")), "2026-10-31"); // 23:30 PST Nov 1
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T08:30:00Z")), "2026-11-01"); // 00:30 PST Nov 2
  assertEquals(lastCompletePacificDay(new Date("2026-11-02T13:17:00Z")), "2026-11-01"); // the 13:17 UTC run
});

Deno.test("UTC stamps equal the old -07:00 stamps for PDT dates (stored rows keep their keys)", () => {
  // UTC 14:00 on 2026-09-29 == 07:00 PDT, which the old scheme stamped "2026-09-29T07:00-07:00".
  assertEquals(Date.parse(stampUtc("2026-09-29T14:00")), Date.parse("2026-09-29T07:00:00-07:00"));
});

Deno.test("stampUtc rejects anything but a bare hourly wall-clock time", () => {
  for (const bad of ["2026-09-29T14:00Z", "2026-09-29T14:00:00", "2026-09-29 14:00", ""]) {
    let threw = false;
    try { stampUtc(bad); } catch { threw = true; }
    assertEquals(threw, true, bad);
  }
});

Deno.test("addDays crosses month ends", () => {
  assertEquals(addDays("2026-09-30", 1), "2026-10-01");
  assertEquals(addDays("2026-10-31", 1), "2026-11-01");
});
