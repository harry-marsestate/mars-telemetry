#!/usr/bin/env node
// Browser check for the floating chat launcher (docs/SECURITY.md, "Floating
// chat launcher"), run against a locally served web/index.html:
//
//   (cd web && python3 -m http.server 8765 --bind 127.0.0.1)
//   node scripts/chat-launcher-check.mjs --dashboard http://127.0.0.1:8765/ --out <dir> [--chrome <path>]
//
// Signs in ONLY the synthetic operator and HEALTH-CUST-B2 users, with an
// admin-generated magic link (.env's service key; nothing is emailed), and
// asks four real questions in total (cost: four ordinary chat turns). Every
// other chat response the check needs (an error, a retry, the rating UI) is
// served by the test from a route, never the real function. Reads only;
// writes nothing. Secrets are never printed.
//
// Checks: launcher fixed while scrolling each data tab; absent on the Chat
// tab and in print; window size bounded (desktop) and a bottom sheet (phone);
// minimise keeps history, draft and scroll; streaming survives minimise and
// lights the unread dot; the thread continues in the Chat tab and back;
// "Ask about this"; error, offline and retry states; sign-out mid-answer then
// another user signing in on the same page sees none of it; role gating of
// panels and "Ask about this" buttons for B2. Screenshots go to --out.
import { mkdirSync, readFileSync } from "node:fs";
import { chromium } from "playwright-core";

const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };
const DASHBOARD = arg("dashboard") ?? "http://127.0.0.1:8765/";
const OUT = arg("out") ?? "chat-launcher-shots";
mkdirSync(OUT, { recursive: true });

const OPERATOR = "harry.c+health-operator@marscap.investments";
const CUSTOMER_B2 = "harry.c+health-customer-b2@marscap.investments";
const OPERATOR_ONLY = ["irrig", "irrigblk", "labhours", "labcost", "cellart", "cellarh", "ferm", "tanks", "fruit"];

const results = [];
const check = (name, ok, detail = "") => { results.push({ name, ok }); console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`); };
const shot = async (page, name) => { await page.screenshot({ path: `${OUT}/${name}.png` }); console.log(`      shot ${name}.png`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function tokenHash(email) {
  if (email !== OPERATOR && email !== CUSTOMER_B2) throw new Error("only the two approved synthetic users");
  const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
    .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "")]));
  const r = await fetch(`${new URL(env.SUPABASE_URL).origin}/auth/v1/admin/generate_link`, {
    method: "POST",
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ type: "magiclink", email }),
  });
  const j = await r.json().catch(() => ({}));
  const h = j.hashed_token ?? j.properties?.hashed_token;
  if (!r.ok || !h) throw new Error(`generate_link failed: HTTP ${r.status}`);
  return h;
}

async function signIn(page, email) {
  const th = await tokenHash(email);
  const err = await page.evaluate(async (t) => (await sb.auth.verifyOtp({ token_hash: t, type: "magiclink" })).error?.message ?? null, th);
  if (err) throw new Error(`verifyOtp: ${err}`);
  await page.waitForFunction(() => document.querySelector(".hdr")?.style.display !== "none" && document.querySelectorAll("#body-vineyard .panel").length > 0, null, { timeout: 90_000 });
  await page.waitForFunction(() => chatRole !== null && chatMsgs.length > 0, null, { timeout: 30_000 }); // greeting in
  await sleep(2500); // let panels finish painting before screenshots
}

const launcherRect = (page) => page.evaluate(() => { const r = document.querySelector("#cw-launch").getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, shown: getComputedStyle(document.querySelector("#cw-launch")).display !== "none" }; });
const winRect = (page) => page.evaluate(() => { const w = document.querySelector("#cw-win"); if (!w || w.hidden) return null; const r = w.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, vw: innerWidth, vh: innerHeight }; });
const tab = (page, t) => page.click(`button.tab[data-tab="${t}"]`);
const waitIdle = (page, ms = 120_000) => page.waitForFunction(() => chatBusy === null, null, { timeout: ms });
const waitText = (page, ms = 90_000) => page.waitForFunction(() => chatMsgs.at(-1)?.state === "streaming" || chatMsgs.at(-1)?.state === "done", null, { timeout: ms });

async function fixedWhileScrolling(page, name) {
  await page.evaluate(() => window.scrollTo(0, 0)); await sleep(200);
  const a = await launcherRect(page);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight)); await sleep(300);
  const b = await launcherRect(page);
  const scrolled = await page.evaluate(() => window.scrollY);
  check(`${name}: launcher fixed while scrolling (scrolled ${Math.round(scrolled)}px)`, a.shown && scrolled > 200 && a.x === b.x && a.y === b.y, JSON.stringify(a));
}

async function signOutMidAnswer(page) {
  await page.evaluate(() => newChat());
  if (!(await page.evaluate(() => cwOpen))) await page.click("#cw-launch");
  await page.fill("#cw-win textarea", "Summarise the last seven days of weather at the estate.");
  await page.keyboard.press("Enter");
  await waitText(page);
  await page.evaluate(() => sb.auth.signOut());
  await page.waitForFunction(() => document.querySelector("#auth-view").classList.contains("on"));
  check("sign-out clears chat state at once", await page.evaluate(() => chatHistory.length === 0 && chatMsgs.length === 0 && chatBusy === null && !document.querySelector("#chatlog").textContent.trim() && !document.querySelector("#cw-win .cw-log").textContent.trim() && document.querySelector("#cw-win").hidden));
  await signIn(page, CUSTOMER_B2);
  await sleep(15_000); // long enough for the aborted operator stream to have finished if it were still running
  const inherit = await page.evaluate(() => ({ history: chatHistory.length, nonGreeting: chatMsgs.filter((m) => !m.greeting).length,
    text: [...document.body.innerText.matchAll(/.{0,50}(Summarise the last seven days|Which block is driest right now).{0,30}/g)].map((m) => m[0]),
    where: [...document.querySelectorAll("body *")].filter((e) => e.children.length === 0 && /Summarise the last seven days|Which block is driest right now/.test(e.textContent)).map((e) => (e.id || e.className || e.tagName) + "<" + (e.parentElement?.id || e.parentElement?.className)) }));
  check("next user on the same page inherits nothing", inherit.history === 0 && inherit.nonGreeting === 0 && inherit.text.length === 0, JSON.stringify(inherit));

}

const executablePath = arg("chrome") ?? process.env.CHROME_PATH;
const browser = await chromium.launch(executablePath ? { executablePath, headless: true } : { channel: "chrome", headless: true });
try { run: { // `break run` ends early (--only-signout)
  // ── Operator, desktop ────────────────────────────────────────────────────
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  // --mock-chat: debug this script without spending real questions (every
  // chat call test-served; the mid-stream checks then fail by design).
  let offline = false;
  if (process.argv.includes("--mock-chat")) await ctx.route("**/functions/v1/chat", (route) => offline ? route.abort("internetdisconnected") : setTimeout(() => route.fulfill({ status: 200, contentType: "text/event-stream",
    body: `data: ${JSON.stringify({ type: "text", text: "(mock answer)" })}\n\ndata: ${JSON.stringify({ type: "done", appended: [{ role: "assistant", content: "(mock answer)" }], provider: "claude" })}\n\n` }), 1500));
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("pageerror:", e.message));
  await page.goto(DASHBOARD, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => typeof sb !== "undefined");
  check("window DOM not built before first open", await page.evaluate(() => !document.querySelector("#cw-win")));
  await signIn(page, OPERATOR);
  if (process.argv.includes("--only-signout")) { await signOutMidAnswer(page); await ctx.close(); break run; }
  await shot(page, "01-desktop-vineyard-launcher");
  await fixedWhileScrolling(page, "vineyard");
  await shot(page, "02-desktop-vineyard-scrolled");
  await tab(page, "winery"); await sleep(3000);
  await fixedWhileScrolling(page, "winery");
  await shot(page, "03-desktop-winery-scrolled");
  await tab(page, "chat"); await sleep(300);
  check("launcher hidden on the Chat tab", !(await launcherRect(page)).shown);
  await tab(page, "vineyard"); await page.evaluate(() => window.scrollTo(0, 0));

  await page.click("#cw-launch");
  const r = await winRect(page);
  check("window opens, bounded on desktop", r && r.w === 400 && r.h <= Math.min(620, r.vh - 160) && r.y > 0 && r.x > r.vw / 2, JSON.stringify(r));
  check("focus moves to the window's input", await page.evaluate(() => document.activeElement === document.querySelector("#cw-win textarea")));
  check("starter prompts shown for an empty thread", await page.evaluate(() => document.querySelectorAll("#cw-win .cw-start").length >= 3));
  check("page context attached and shown", /Vineyard Data/.test(await page.textContent("#cw-win .cw-ctx")));
  // Any panel control on screen and outside the window still takes clicks.
  check("dashboard behind stays usable (panel controls outside the window take clicks)", await page.evaluate(() => {
    const w = document.querySelector("#cw-win").getBoundingClientRect();
    const b = [...document.querySelectorAll("#body-vineyard .rng button, #body-vineyard .p-ask")].find((x) => { const r = x.getBoundingClientRect(); return r.top > 80 && r.bottom < innerHeight && r.right < w.left; });
    if (!b) return false; const r = b.getBoundingClientRect(); return b.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)); }));
  await shot(page, "04-desktop-window-open");

  // Q1 (real): ask from the window, minimise mid-answer.
  await page.fill("#cw-win textarea", "Which block is driest right now?");
  await page.keyboard.press("Enter");
  await waitText(page);
  await page.keyboard.press("Escape");
  check("Esc minimises and returns focus to the launcher", await page.evaluate(() => document.querySelector("#cw-win").hidden && document.activeElement === document.querySelector("#cw-launch")));
  check("answer still streaming after minimise", await page.evaluate(() => chatBusy !== null));
  await waitIdle(page);
  check("answer committed while minimised", await page.evaluate(() => chatHistory.length >= 2 && chatMsgs.at(-1).state === "done"));
  check("unread dot on the launcher", await page.evaluate(() => !document.querySelector("#cw-dot").hidden && /new answer/.test(document.querySelector("#cw-launch").getAttribute("aria-label"))));
  await page.evaluate(() => window.scrollTo(0, 0));
  await shot(page, "05-desktop-unread-dot");

  await page.click("#cw-launch");
  check("reopen clears the dot and shows the answer", await page.evaluate(() => document.querySelector("#cw-dot").hidden && /Mars Telemetry/.test(document.querySelector("#cw-win .cw-log").textContent)));
  await shot(page, "06-desktop-window-answer");
  await page.fill("#cw-win textarea", "draft I have not sent");
  const scrollable = await page.evaluate(() => { const l = document.querySelector("#cw-win .cw-log"); l.scrollTop = 40; l.dispatchEvent(new Event("scroll")); return l.scrollHeight - l.clientHeight > 40; });
  await page.click('#cw-win [data-cw="min"]');
  await page.click("#cw-launch");
  check("minimise/reopen keeps the unsent draft", (await page.inputValue("#cw-win textarea")) === "draft I have not sent");
  check("minimise/reopen keeps the scroll position", scrollable && await page.evaluate(() => document.querySelector("#cw-win .cw-log").scrollTop === 40), scrollable ? "" : "(log not scrollable)");
  check("draft is shared with the Chat tab input", (await page.inputValue("#chatin")) === "draft I have not sent");

  // Continue the same thread in the Chat tab (Q2, real).
  await page.click('#cw-win [data-cw="expand"]');
  check("expand goes to the Chat tab with the thread", await page.evaluate(() => state.tab === "chat" && /Which block is driest/.test(document.querySelector("#chatlog").textContent)));
  await page.fill("#chatin", "How does that compare with a week ago?");
  await page.click("#send");
  await waitIdle(page);
  await shot(page, "07-desktop-chat-tab-continued");
  await tab(page, "vineyard");
  await page.click("#cw-launch");
  check("follow-up asked in the Chat tab appears in the window", await page.evaluate(() => /compare with a week ago/.test(document.querySelector("#cw-win .cw-log").textContent) && chatMsgs.filter((m) => m.who === "u").length === 2));
  await shot(page, "08-desktop-window-continued");
  await page.click('#cw-win [data-cw="min"]');

  // Ask about this (prefill only, not sent).
  await page.click('.panel[data-panel-id="soilmoist"] .p-ask');
  check("Ask about this: panel attached + question prefilled, nothing sent", await page.evaluate(() => /Soil moisture/.test(document.querySelector("#cw-win .cw-ctx").textContent) && /Soil moisture/.test(document.querySelector("#cw-win textarea").value) && chatBusy === null));
  await shot(page, "09-desktop-ask-about-this");
  await page.click('#cw-win [data-ctx="clear"]');
  check("context can be cleared", /Nothing attached/.test(await page.textContent("#cw-win .cw-ctx")));
  await page.click('#cw-win [data-ctx="add"]');

  // Error states, served by the test (never the real function).
  await page.route("**/functions/v1/chat", (route) => route.fulfill({ status: 413, contentType: "application/json", body: JSON.stringify({ code: "history_too_large", error: "This conversation has grown too long to continue. Start a new chat to keep going." }) }));
  await page.fill("#cw-win textarea", "test: 413");
  await page.keyboard.press("Enter");
  await waitIdle(page);
  check("413 shown with a New chat action", await page.evaluate(() => /grown too long/.test(document.querySelector("#cw-win .cw-log").textContent) && !!document.querySelector('#cw-win [data-act="new"]')));
  await shot(page, "10-desktop-error-413");
  await page.unroute("**/functions/v1/chat");
  await ctx.setOffline(true); offline = true;
  await page.fill("#cw-win textarea", "test: offline");
  await page.keyboard.press("Enter");
  await waitIdle(page);
  check("offline state with Retry", await page.evaluate(() => /offline/.test(document.querySelector("#cw-win .cw-log").textContent) && !!document.querySelector('#cw-win [data-act="retry"]')));
  await shot(page, "11-desktop-offline");
  await ctx.setOffline(false); offline = false;
  await page.route("**/functions/v1/chat", (route) => route.fulfill({ status: 200, contentType: "text/event-stream",
    body: `data: ${JSON.stringify({ type: "text", text: "(test-served retry answer)" })}\n\ndata: ${JSON.stringify({ type: "done", appended: [{ role: "assistant", content: "(test-served retry answer)" }], provider: "claude" })}\n\n` }));
  if (await page.$('#cw-win [data-act="retry"]')) { await page.click('#cw-win [data-act="retry"]'); await waitIdle(page); }
  check("Retry re-sends and replaces the failure", await page.evaluate(() => chatMsgs.at(-1).state === "done" && chatMsgs.filter((m) => m.text === "test: offline").length === 1));
  await page.unroute("**/functions/v1/chat");

  await page.emulateMedia({ media: "print" });
  check("launcher and window hidden in print", await page.evaluate(() => getComputedStyle(document.querySelector("#cw-launch")).display === "none" && getComputedStyle(document.querySelector("#cw-win")).display === "none"));
  await page.emulateMedia({ media: "screen" });

  // Sign-out mid-answer, then another user on the same page (Q3, real, cut short).
  await signOutMidAnswer(page);

  // ── Customer B2: role gating unchanged ───────────────────────────────────
  // Each data tab as B2 renders it. (Only tabs B2 has rendered: a hidden tab
  // can still hold the previous user's DOM -- a pre-existing dashboard issue,
  // reported separately, not part of the chat.)
  for (const t of ["vineyard", "winery"]) {
    await tab(page, t); await sleep(t === "winery" ? 5000 : 500);
    const ids = await page.evaluate((t) => [...document.querySelectorAll(`#body-${t} .panel[data-panel-id]`)].map((p) => p.dataset.panelId), t);
    const op = ids.filter((id) => OPERATOR_ONLY.includes(id));
    check(`B2 ${t}: no operator-only panels rendered`, op.length === 0, op.join(","));
    const asks = await page.evaluate((t) => [...document.querySelectorAll(`#body-${t} .p-ask`)].map((b) => b.closest(".panel").dataset.panelId), t);
    check(`B2 ${t}: every 'Ask about this' belongs to a panel B2 can see`, asks.every((id) => !OPERATOR_ONLY.includes(id)), `${asks.length} buttons`);
  }
  await tab(page, "vineyard");
  check("B2: operator model selector hidden", await page.evaluate(() => document.querySelector("#chatModelRow").style.display === "none"));
  await page.click("#cw-launch");
  await page.waitForFunction(() => /block B2/.test(document.querySelector("#cw-win .cw-ctx").textContent), null, { timeout: 10_000 }).catch(() => {});
  check("B2: context names only B2", /block B2 ·/.test(await page.textContent("#cw-win .cw-ctx")));
  await shot(page, "12-desktop-customer-window");
  // Q4 (real): a starter prompt.
  await page.click("#cw-win .cw-start >> nth=1");
  await waitIdle(page);
  check("B2: starter prompt answered", await page.evaluate(() => chatMsgs.at(-1).state === "done"));
  await shot(page, "13-desktop-customer-answer");

  // ── Phone width (same B2 session) ────────────────────────────────────────
  await page.click('#cw-win [data-cw="min"]');
  await page.setViewportSize({ width: 390, height: 844 });
  await sleep(500);
  await fixedWhileScrolling(page, "phone vineyard");
  await page.evaluate(() => window.scrollTo(0, 400));
  await shot(page, "14-phone-launcher");
  await page.click("#cw-launch");
  const pr = await winRect(page);
  check("phone: bottom sheet, full width, ~88% height", pr && pr.w === 390 && Math.abs(pr.y + pr.h - 844) < 2 && pr.h > 700 && pr.h < 760, JSON.stringify(pr));
  check("phone: launcher steps aside while open", !(await launcherRect(page)).shown);
  check("phone: obvious close button", await page.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-close-x")).display !== "none"));
  check("phone: conversation kept across the resize", await page.evaluate(() => /Mars Telemetry/.test(document.querySelector("#cw-win .cw-log").textContent) && chatMsgs.filter((m) => m.who === "u").length === 1));
  await shot(page, "15-phone-sheet");
  await page.click('#cw-win [data-cw="min"]');
  check("phone: close returns to the page", await page.evaluate(() => document.querySelector("#cw-win").hidden) && (await launcherRect(page)).shown);
  await ctx.close();

  // ── Rating + "This was wrong" UI (flag forced on, everything test-served) ─
  const ctx2 = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const p2 = await ctx2.newPage();
  const html = await (await fetch(DASHBOARD)).text();
  await p2.route(DASHBOARD, (route) => route.fulfill({ status: 200, contentType: "text/html", body: html.replace("const CHAT_EVENTS_ENABLED = false;", "const CHAT_EVENTS_ENABLED = true;") }));
  const events = [];
  await p2.route("**/rest/v1/chat_events*", (route) => { events.push(JSON.parse(route.request().postData())); route.fulfill({ status: 201, body: "" }); });
  await p2.route("**/functions/v1/chat", (route) => route.fulfill({ status: 200, contentType: "text/event-stream",
    body: `data: ${JSON.stringify({ type: "text", text: "**B2** is driest at 18.2% VWC (test-served answer)." })}\n\ndata: ${JSON.stringify({ type: "done", appended: [{ role: "assistant", content: "x" }], provider: "claude" })}\n\n` }));
  await p2.goto(DASHBOARD, { waitUntil: "domcontentloaded" });
  await p2.waitForFunction(() => typeof sb !== "undefined");
  await signIn(p2, OPERATOR);
  await p2.click("#cw-launch");
  await p2.fill("#cw-win textarea", "Which block is driest?");
  await p2.keyboard.press("Enter");
  await waitIdle(p2);
  await shot(p2, "16-desktop-rating-controls");
  await p2.click('#cw-win [data-act="flag"]');
  await shot(p2, "17-desktop-flag-notice");
  check("no text sent before the flag is confirmed", events.every((e) => !("question" in e) && !("answer" in e)), JSON.stringify(events.map((e) => e.event)));
  await p2.click('#cw-win [data-act="flag-send"]');
  await p2.waitForFunction(() => /Reported/.test(document.querySelector("#cw-win .cw-log").textContent));
  const flag = events.at(-1);
  check("flag carries question + answer text, nothing else does", flag.event === "flag_wrong" && /Which block is driest\?/.test(flag.question) && /18\.2%/.test(flag.answer) && events.slice(0, -1).every((e) => !("question" in e)), JSON.stringify(events.map((e) => e.event)));
  await shot(p2, "18-desktop-flag-sent");
  await ctx2.close();
} } finally {
  await browser.close();
}
const bad = results.filter((r) => !r.ok).length;
console.log(`\n${results.length} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
