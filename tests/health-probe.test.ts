// Deno tests for supabase/functions/health-probe/probes.ts:
//   npx deno test --no-lock --config supabase/functions/health-probe/deno.json -A tests/health-probe.test.ts
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import {
  ANTHROPIC_CHAT_MODEL, KIMI_BASE_URL, KIMI_MODEL, pacificMidnightUtcHour, probeAnthropic, probeFireworks, probeInnovint,
  probeOpenMeteo, probeResend, request, runProbes,
} from "../supabase/functions/health-probe/probes.ts";

const SECRETS = { INNOVINT_TOKEN: "tok_SECRET_innovint_123", ANTHROPIC_API_KEY: "sk-ant-SECRET-abc", KIMI_API_KEY: "fw_SECRET_kimi", RESEND_API_KEY: "re_SECRET_resend", RESEND_FROM_EMAIL: "Mars <alerts@marsestates.com>" };
const env = (over: Record<string, string | undefined> = {}) => (n: string) => ({ ...SECRETS, ...over } as Record<string, string | undefined>)[n];
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const noSecrets = (x: unknown) => { const s = JSON.stringify(x); for (const v of Object.values(SECRETS)) if (v.includes("SECRET")) assert(!s.includes(v), `secret leaked: ${s}`); };

Deno.test("constants are pinned to what chat actually calls", async () => {
  const chat = await Deno.readTextFile(new URL("../supabase/functions/chat/index.ts", import.meta.url));
  const kimi = await Deno.readTextFile(new URL("../supabase/functions/chat/kimi.ts", import.meta.url));
  assert(chat.includes(`model: "${ANTHROPIC_CHAT_MODEL}"`), "chat's Anthropic model changed: update ANTHROPIC_CHAT_MODEL");
  assert(kimi.includes(`export const KIMI_MODEL = "${KIMI_MODEL}";`));
  assert(kimi.includes(`export const KIMI_BASE_URL = "${KIMI_BASE_URL}";`));
  const innovint = await Deno.readTextFile(new URL("../supabase/functions/ingest-innovint/index.ts", import.meta.url));
  assert(innovint.includes('const BASE_URL = "https://sutter.innovint.us/api/v1";'));
});

Deno.test("Pacific midnight in UTC follows DST", () => {
  assertEquals(pacificMidnightUtcHour("2026-09-29"), 7);
  assertEquals(pacificMidnightUtcHour("2026-11-02"), 8);
  assertEquals(pacificMidnightUtcHour("2027-03-15"), 7);
});

Deno.test("request retries once on 5xx / network error, never on 4xx", async () => {
  let n = 0;
  const flaky = () => { n++; return Promise.resolve(n === 1 ? new Response("x", { status: 503 }) : json(200, { ok: 1 })); };
  const r = await request(flaky, "https://x", {}, () => Promise.resolve());
  assertEquals([r.status, r.attempts, n], [200, 2, 2]);
  n = 0;
  const r2 = await request(() => { n++; return Promise.resolve(json(401, {})); }, "https://x", {}, () => Promise.resolve());
  assertEquals([r2.status, r2.attempts, n], [401, 1, 1]);
  const r3 = await request(() => Promise.reject(new TypeError("boom")), "https://x", {}, () => Promise.resolve());
  assertEquals([r3.status, r3.attempts, r3.error], [null, 2, "TypeError"]);
});

Deno.test("InnoVint: vessels?limit=1 with the Access-Token header; 401 -> fail", async () => {
  let seen: [string, Headers] | null = null;
  const ok = await probeInnovint(env(), (url, init) => { seen = [url, new Headers(init?.headers)]; return Promise.resolve(json(200, { results: [{ data: {} }], pagination: {} })); });
  assertEquals(ok.status, "pass");
  assertMatch(seen![0], /\/wineries\/wnry_2PW0KJ93L726WKKG54OQE1RY\/vessels\?limit=1$/);
  assertEquals(seen![1].get("Authorization"), `Access-Token ${SECRETS.INNOVINT_TOKEN}`);
  const bad = await probeInnovint(env(), () => Promise.resolve(json(401, { error: `bad token ${SECRETS.INNOVINT_TOKEN}` })));
  assertEquals([bad.status, bad.detail], ["fail", "InnoVint rejected the token"]);
  noSecrets([ok, bad]);
  assertEquals((await probeInnovint(env({ INNOVINT_TOKEN: undefined }), () => Promise.reject())).status, "fail");
});

Deno.test("Open-Meteo: the ingest's own URL for the last complete Pacific day; counts only that day's hours", async () => {
  const now = new Date("2026-09-30T12:10:00Z"); // 05:10 PDT -> last complete Pacific day 2026-09-29
  const times = Array.from({ length: 48 }, (_, i) => `2026-09-${i < 24 ? "29" : "30"}T${String(i % 24).padStart(2, "0")}:00`);
  let url = "";
  const temps = times.map((_, i) => (i >= 7 && i < 31 ? 60 : null));
  const r = await probeOpenMeteo(now, (u) => { url = u; return Promise.resolve(json(200, { utc_offset_seconds: 0, hourly: { time: times, temperature_2m: temps } })); }, "weather");
  assertMatch(url, /^https:\/\/archive-api\.open-meteo\.com\/v1\/archive\?.*start_date=2026-09-29&end_date=2026-09-30&hourly=temperature_2m%2Crelative_humidity_2m%2Cprecipitation&temperature_unit=fahrenheit&timezone=UTC.*&models=ecmwf_ifs$/);
  assertEquals(r.check_id, "source.open_meteo.ecmwf_ifs");
  assertEquals([r.status, r.observed.non_null_hours, r.observed.hours], ["pass", 24, 48]);
  const partial = await probeOpenMeteo(now, () => Promise.resolve(json(200, { utc_offset_seconds: 0, hourly: { time: times, temperature_2m: temps.map((v, i) => (i > 20 ? null : v)) } })), "weather");
  assertEquals(partial.status, "warn");
  const notUtc = await probeOpenMeteo(now, () => Promise.resolve(json(200, { utc_offset_seconds: -25200, hourly: { time: times, temperature_2m: temps } })), "weather");
  assertEquals(notUtc.status, "fail");
  const land = await probeOpenMeteo(now, (u) => { url = u; return Promise.resolve(json(200, { utc_offset_seconds: 0, hourly: { time: times, soil_moisture_0_to_7cm: times.map(() => null) } })); }, "soil");
  assertEquals(land.status, "pass", "ERA5-Land lag is informational");
  assertMatch(url, /models=era5_land/);
  assertEquals((await probeOpenMeteo(now, () => Promise.resolve(json(400, { error: true, reason: "end_date out of range" })), "weather")).status, "fail");
});

Deno.test("Anthropic: GET the chat model; 404 (retired model) and 401 fail", async () => {
  let h: Headers | null = null; let u = "";
  const ok = await probeAnthropic(env(), (url, init) => { u = url; h = new Headers(init?.headers); return Promise.resolve(json(200, { id: ANTHROPIC_CHAT_MODEL, type: "model" })); });
  assertEquals(ok.status, "pass");
  assertEquals(u, `https://api.anthropic.com/v1/models/${ANTHROPIC_CHAT_MODEL}`);
  assertEquals([h!.get("x-api-key"), h!.get("anthropic-version")], [SECRETS.ANTHROPIC_API_KEY, "2023-06-01"]);
  assertMatch((await probeAnthropic(env(), () => Promise.resolve(json(404, {})))).detail!, /not available/);
  assertMatch((await probeAnthropic(env(), () => Promise.resolve(json(401, {})))).detail!, /rejected/);
  noSecrets(ok);
});

Deno.test("Fireworks: optional unless CHAT_MODEL_PROVIDER=kimi; model must be listed", async () => {
  assertEquals((await probeFireworks(env({ KIMI_API_KEY: undefined }), () => Promise.reject())).status, "pass");
  assertEquals((await probeFireworks(env({ KIMI_API_KEY: undefined, CHAT_MODEL_PROVIDER: "kimi" }), () => Promise.reject())).status, "fail");
  assertEquals((await probeFireworks(env(), () => Promise.resolve(json(200, { data: [{ id: KIMI_MODEL }] })))).status, "pass");
  assertEquals((await probeFireworks(env(), () => Promise.resolve(json(200, { data: [{ id: "other" }] })))).status, "warn");
  assertEquals((await probeFireworks(env(), () => Promise.resolve(json(401, {})))).status, "fail");
});

Deno.test("Resend: send-only key (restricted_api_key) passes; verified domain passes; invalid key fails", async () => {
  assertEquals((await probeResend(env(), () => Promise.resolve(json(401, { name: "restricted_api_key", message: "restricted" })))).status, "pass");
  assertEquals((await probeResend(env(), () => Promise.resolve(json(200, { data: [{ name: "marsestates.com", status: "verified" }] })))).status, "pass");
  assertEquals((await probeResend(env(), () => Promise.resolve(json(200, { data: [{ name: "marsestates.com", status: "pending" }] })))).status, "warn");
  assertEquals((await probeResend(env(), () => Promise.resolve(json(400, { name: "validation_error", message: "API key is invalid" })))).status, "fail");
  assertEquals((await probeResend(env({ RESEND_API_KEY: undefined }), () => Promise.reject())).status, "fail");
});

Deno.test("runProbes: six results, sequential, a crashing probe becomes 'error' without its message", async () => {
  let inFlight = 0, maxInFlight = 0;
  const f = async (url: string) => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 1));
    inFlight--;
    if (url.includes("anthropic")) throw new Error(`leak ${SECRETS.ANTHROPIC_API_KEY}`);
    return json(200, {});
  };
  const results = await runProbes(env(), f as never, new Date("2026-09-30T12:10:00Z"));
  assertEquals(results.map((r) => r.check_id), ["source.innovint.api", "source.open_meteo.ecmwf_ifs", "source.open_meteo.era5_land", "source.anthropic.model", "source.fireworks.model", "source.resend.api"]);
  assertEquals(maxInFlight, 1);
  noSecrets(results);
});
