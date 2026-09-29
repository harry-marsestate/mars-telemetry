// ingest-climate-2026's upsert/refresh window (window.ts).
//   npx deno test --no-lock tests/ingest-climate-window.test.ts
import { assertEquals } from "jsr:@std/assert@1";
import { lastCompletePacificDay, lastElapsedHourMs } from "../supabase/functions/ingest-climate-2026/window.ts";

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
