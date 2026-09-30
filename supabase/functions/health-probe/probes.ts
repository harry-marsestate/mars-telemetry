// P2 upstream probes (docs/SECURITY.md, "Nightly health checks"). Each probe
// makes ONE zero-cost read-only request to a service production depends on,
// with the same credential production uses, and turns the answer into a
// health result. Nothing a probe records contains a secret or a response
// body: status codes, timings, counts and a few named fields only.
import { addDays, archiveUrl, lastCompletePacificDay } from "../ingest-climate-2026/window.ts";

// Pinned to the values chat uses (tests/health-probe.test.ts reads chat's
// source and fails if they drift).
export const ANTHROPIC_CHAT_MODEL = "claude-sonnet-5";
export const KIMI_MODEL = "accounts/fireworks/models/kimi-k3";
export const KIMI_BASE_URL = "https://api.fireworks.ai/inference/v1";
export const INNOVINT_BASE_URL = "https://sutter.innovint.us/api/v1";
export const INNOVINT_DEFAULT_WINERY = "wnry_2PW0KJ93L726WKKG54OQE1RY";

export type Status = "pass" | "warn" | "fail" | "error";
export interface ProbeResult {
  check_id: string;
  status: Status;
  observed: Record<string, unknown>;
  expected: Record<string, unknown>;
  detail?: string;
}
export type Env = (name: string) => string | undefined;
export type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

const TIMEOUT_MS = 15_000;

// The UTC hour at which Pacific day `day` starts (7 in PDT, 8 in PST).
export function pacificMidnightUtcHour(day: string): number {
  const h = Number(new Intl.DateTimeFormat("en-US", { timeZone: "America/Los_Angeles", hour: "numeric", hourCycle: "h23" })
    .format(new Date(`${day}T00:00:00Z`)));
  return 24 - h;
}

// One request, one retry after 3s on a network error or 5xx (a single blip at
// 12:10 UTC shouldn't page anyone); never retried on 4xx.
export async function request(fetchFn: Fetch, url: string, init: RequestInit = {}, sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))) {
  let last: { status: number | null; ms: number; body: unknown; error?: string } = { status: null, ms: 0, body: null };
  for (let attempt = 1; attempt <= 2; attempt++) {
    const t0 = Date.now();
    try {
      const resp = await fetchFn(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
      const text = await resp.text();
      let body: unknown = null;
      try { body = JSON.parse(text); } catch { body = null; }
      last = { status: resp.status, ms: Date.now() - t0, body };
      if (resp.status < 500) return { ...last, attempts: attempt };
    } catch (err) {
      last = { status: null, ms: Date.now() - t0, body: null, error: err instanceof Error ? err.name : "error" };
    }
    if (attempt === 1) await sleep(3000);
  }
  return { ...last, attempts: 2 };
}

const base = (r: { status: number | null; ms: number; attempts: number; error?: string }) =>
  ({ http_status: r.status, ms: r.ms, attempts: r.attempts, ...(r.error ? { network_error: r.error } : {}) });

export async function probeInnovint(env: Env, fetchFn: Fetch): Promise<ProbeResult> {
  const id = "source.innovint.api";
  const expected = { http_status: 200, results: "array" };
  const token = env("INNOVINT_TOKEN");
  if (!token) return { check_id: id, status: "fail", observed: { configured: false }, expected, detail: "INNOVINT_TOKEN is not set" };
  const winery = env("INNOVINT_WINERY_ID") ?? INNOVINT_DEFAULT_WINERY;
  const r = await request(fetchFn, `${INNOVINT_BASE_URL}/wineries/${winery}/vessels?limit=1`, { headers: { Authorization: `Access-Token ${token}` } });
  // deno-lint-ignore no-explicit-any
  const results = (r.body as any)?.results;
  const observed = { ...base(r), results_returned: Array.isArray(results) ? results.length : null };
  if (r.status === 200 && Array.isArray(results)) return { check_id: id, status: "pass", observed, expected };
  return { check_id: id, status: "fail", observed, expected,
    detail: r.status === 401 || r.status === 403 ? "InnoVint rejected the token" : r.status === null ? "no response from InnoVint" : "unexpected InnoVint response" };
}

// The archive request exactly as ingest-climate-2026 builds it, for the last
// complete Pacific day (the day the next ingest will store).
export async function probeOpenMeteo(now: Date, fetchFn: Fetch, variant: "era5" | "era5_land"): Promise<ProbeResult> {
  const id = variant === "era5" ? "source.open_meteo.archive" : "source.open_meteo.archive_era5_land";
  const day = lastCompletePacificDay(now);
  const vars = variant === "era5" ? ["temperature_2m", "relative_humidity_2m", "precipitation"] : ["soil_moisture_0_to_7cm", "soil_temperature_0_to_7cm"];
  // The ingest's window runs Pacific midnight to midnight in UTC hours, so it asks for [day, day+1].
  const r = await request(fetchFn, archiveUrl(day, addDays(day, 1), vars, variant === "era5_land" ? "era5_land" : undefined));
  // deno-lint-ignore no-explicit-any
  const body = r.body as any;
  const times: string[] = Array.isArray(body?.hourly?.time) ? body.hourly.time : [];
  const first: unknown[] = Array.isArray(body?.hourly?.[vars[0]]) ? body.hourly[vars[0]] : [];
  // Only the 24 hours of the Pacific day itself (the response is UTC hours).
  const startIdx = times.indexOf(`${day}T${String(pacificMidnightUtcHour(day)).padStart(2, "0")}:00`);
  const dayValues = startIdx >= 0 ? first.slice(startIdx, startIdx + 24) : [];
  const nonNull = dayValues.filter((v) => v !== null && v !== undefined).length;
  const observed = { ...base(r), day, hours: times.length, non_null_hours: nonNull, utc_offset_seconds: body?.utc_offset_seconds ?? null };
  const expected = { http_status: 200, utc_offset_seconds: 0, hours: 48, non_null_hours: variant === "era5" ? ">= 24" : "informational (ERA5-Land lags ~5 days)" };
  if (r.status !== 200 || !times.length) {
    return { check_id: id, status: "fail", observed, expected, detail: r.status === null ? "no response from Open-Meteo" : "Open-Meteo archive request failed" };
  }
  if (body.utc_offset_seconds !== 0) return { check_id: id, status: "fail", observed, expected, detail: "response not in UTC: the ingest would refuse it" };
  if (variant === "era5" && nonNull < 24) return { check_id: id, status: "warn", observed, expected, detail: "fewer than 24 hours of data for the last complete Pacific day" };
  return { check_id: id, status: "pass", observed, expected };
}

export async function probeAnthropic(env: Env, fetchFn: Fetch): Promise<ProbeResult> {
  const id = "source.anthropic.model";
  const expected = { http_status: 200, model: ANTHROPIC_CHAT_MODEL };
  const key = env("ANTHROPIC_API_KEY");
  if (!key) return { check_id: id, status: "fail", observed: { configured: false }, expected, detail: "ANTHROPIC_API_KEY is not set" };
  const r = await request(fetchFn, `https://api.anthropic.com/v1/models/${ANTHROPIC_CHAT_MODEL}`, {
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01" },
  });
  // deno-lint-ignore no-explicit-any
  const observed = { ...base(r), model: (r.body as any)?.id ?? null };
  if (r.status === 200 && observed.model === ANTHROPIC_CHAT_MODEL) return { check_id: id, status: "pass", observed, expected };
  return { check_id: id, status: "fail", observed, expected,
    detail: r.status === 401 ? "Anthropic rejected the API key" : r.status === 404 ? `model ${ANTHROPIC_CHAT_MODEL} not available: chat would fail` : "unexpected Anthropic response" };
}

// Kimi via Fireworks is an optional chat provider (CHAT_MODEL_PROVIDER=kimi
// or a per-request override); it matters only if its key is configured.
export async function probeFireworks(env: Env, fetchFn: Fetch): Promise<ProbeResult> {
  const id = "source.fireworks.model";
  const expected = { http_status: 200, model_listed: true };
  const key = env("KIMI_API_KEY");
  if (!key) {
    const required = env("CHAT_MODEL_PROVIDER") === "kimi";
    return { check_id: id, status: required ? "fail" : "pass", observed: { configured: false }, expected,
      detail: required ? "CHAT_MODEL_PROVIDER=kimi but KIMI_API_KEY is not set" : "not configured (optional provider)" };
  }
  const r = await request(fetchFn, `${KIMI_BASE_URL}/models`, { headers: { Authorization: `Bearer ${key}` } });
  // deno-lint-ignore no-explicit-any
  const ids: string[] = Array.isArray((r.body as any)?.data) ? (r.body as any).data.map((m: { id?: string }) => m?.id) : [];
  const observed = { ...base(r), models_listed: ids.length, model_listed: ids.includes(KIMI_MODEL) };
  if (r.status === 200 && observed.model_listed) return { check_id: id, status: "pass", observed, expected };
  if (r.status === 200) return { check_id: id, status: "warn", observed, expected, detail: `${KIMI_MODEL} is not in the key's model list` };
  return { check_id: id, status: "fail", observed, expected, detail: r.status === 401 || r.status === 403 ? "Fireworks rejected the API key" : "unexpected Fireworks response" };
}

// Resend: GET /domains costs nothing and sends nothing. A send-only key answers
// 401 "restricted_api_key", which still proves the key is valid.
export async function probeResend(env: Env, fetchFn: Fetch): Promise<ProbeResult> {
  const id = "source.resend.api";
  const expected = { key: "valid", sending_domain: "verified (when the key can list domains)" };
  const key = env("RESEND_API_KEY");
  if (!key) return { check_id: id, status: "fail", observed: { configured: false }, expected, detail: "RESEND_API_KEY is not set: admin approval emails can't be sent" };
  const r = await request(fetchFn, "https://api.resend.com/domains", { headers: { Authorization: `Bearer ${key}` } });
  // deno-lint-ignore no-explicit-any
  const body = r.body as any;
  if (r.status === 401 && body?.name === "restricted_api_key") {
    return { check_id: id, status: "pass", observed: { ...base(r), key: "valid (send-only)" }, expected };
  }
  if (r.status === 200 && Array.isArray(body?.data)) {
    const fromDomain = (env("RESEND_FROM_EMAIL") ?? "").split("@")[1]?.replace(/>.*$/, "").toLowerCase() ?? "";
    // deno-lint-ignore no-explicit-any
    const domain = body.data.find((d: any) => String(d?.name ?? "").toLowerCase() === fromDomain);
    const observed = { ...base(r), key: "valid", sending_domain_status: domain?.status ?? (fromDomain ? "not found" : "RESEND_FROM_EMAIL unset") };
    return domain?.status === "verified"
      ? { check_id: id, status: "pass", observed, expected }
      : { check_id: id, status: "warn", observed, expected, detail: "the sending domain isn't verified in Resend" };
  }
  return { check_id: id, status: "fail", observed: { ...base(r), key: "rejected or unexpected response" }, expected,
    detail: r.status === 401 || r.status === 403 || r.status === 400 ? "Resend rejected the API key" : "unexpected Resend response" };
}

export async function runProbes(env: Env, fetchFn: Fetch, now = new Date()): Promise<ProbeResult[]> {
  const probes: [string, () => Promise<ProbeResult>][] = [
    ["source.innovint.api", () => probeInnovint(env, fetchFn)],
    ["source.open_meteo.archive", () => probeOpenMeteo(now, fetchFn, "era5")],
    ["source.open_meteo.archive_era5_land", () => probeOpenMeteo(now, fetchFn, "era5_land")],
    ["source.anthropic.model", () => probeAnthropic(env, fetchFn)],
    ["source.fireworks.model", () => probeFireworks(env, fetchFn)],
    ["source.resend.api", () => probeResend(env, fetchFn)],
  ];
  // Sequential: one request at a time to each upstream.
  const out: ProbeResult[] = [];
  for (const [id, probe] of probes) {
    try {
      out.push(await probe());
    } catch (err) {
      out.push({ check_id: id, status: "error", observed: {}, expected: {}, detail: `probe crashed: ${err instanceof Error ? err.name : "error"}` });
    }
  }
  return out;
}
