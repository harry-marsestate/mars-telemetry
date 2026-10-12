#!/usr/bin/env node
// Browser check for the floating chat launcher (docs/SECURITY.md, "Floating
// chat launcher"), run against a locally served web/index.html:
//
//   (cd web && python3 -m http.server 8765 --bind 127.0.0.1)
//   node scripts/chat-launcher-check.mjs --dashboard http://127.0.0.1:8765/ --out <dir> [--real-question] [--chrome <path>]
//
// Signs in ONLY the synthetic operator and HEALTH-CUST-B2 users, with an
// admin-generated magic link (.env's service key; nothing is emailed).
//
// Chat answers are MOCKED IN THE PAGE by default: sb.functions.invoke('chat')
// is replaced with a ReadableStream that really streams (text over ~2s) and
// honours the abort signal, so mid-stream behaviour is exercised without
// spending real questions. Error states use routes on the real fetch path.
// --real-question asks exactly ONE real question (operator, from the window).
// Reads only; writes nothing. Secrets are never printed.
import { mkdirSync, readFileSync } from "node:fs";
import { chromium } from "playwright-core";

const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };
const DASHBOARD = arg("dashboard") ?? "http://127.0.0.1:8765/";
const OUT = arg("out") ?? "chat-launcher-shots";
const REAL = process.argv.includes("--real-question");
mkdirSync(OUT, { recursive: true });

const OPERATOR = "harry.c+health-operator@marscap.investments";
const CUSTOMER_B2 = "harry.c+health-customer-b2@marscap.investments";
const OPERATOR_ONLY = ["irrig", "irrigblk", "labhours", "labcost", "cellart", "cellarh", "ferm", "tanks", "fruit"];

const results = [];
const check = (name, ok, detail = "") => { results.push({ name, ok: !!ok }); console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`); };
const shot = async (page, name) => { await page.screenshot({ path: `${OUT}/${name}.png` }); console.log(`      shot ${OUT}/${name}.png`); };
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

async function open(page) {
  await page.goto(DASHBOARD, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => typeof sb !== "undefined");
  // In-page chat mock. window.__chatMock: 'stream' (default) | 'real' (the
  // real function, e.g. for routed error responses or the one real question).
  // Patched on the prototype: `sb.functions` is a getter returning a NEW
  // client on every access, so patching one instance silently does nothing
  // (that mistake once sent every "mocked" question to the real function).
  await page.evaluate(() => {
    const proto = Object.getPrototypeOf(sb.functions);
    const real = proto.invoke;
    window.__chatMock = "stream";
    proto.invoke = async function (name, opts) {
      if (name !== "chat" || window.__chatMock === "real") return real.call(this, name, opts);
      const q = opts.body.messages.at(-1).content;
      const words = `(mock answer) You asked: ${String(q).split("\n").at(-1)}. Here is a streamed reply in several parts so it takes a moment to arrive.`.split(" ");
      const enc = new TextEncoder(), sig = opts.signal;
      const body = new ReadableStream({ async start(c) {
        for (const w of words) {
          if (sig?.aborted) { c.error(new DOMException("aborted", "AbortError")); return; }
          c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "text", text: w + " " })}\n\n`));
          await new Promise((r) => setTimeout(r, 90));
        }
        c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "done", appended: [{ role: "assistant", content: words.join(" ") }], provider: "claude" })}\n\n`));
        c.close();
      } });
      return { data: { body }, error: null };
    };
  });
  if (!(await page.evaluate(() => Object.getPrototypeOf(sb.functions).invoke.toString().includes("__chatMock")))) throw new Error("chat mock not installed");
}

async function signIn(page, email) {
  const th = await tokenHash(email);
  const err = await page.evaluate(async (t) => (await sb.auth.verifyOtp({ token_hash: t, type: "magiclink" })).error?.message ?? null, th);
  if (err) throw new Error(`verifyOtp: ${err}`);
  await page.waitForFunction(() => document.querySelector(".hdr")?.style.display !== "none" && document.querySelectorAll("#body-vineyard .panel").length > 0, null, { timeout: 90_000 });
  await page.waitForFunction(() => chatRole !== null && chatMsgs.length > 0, null, { timeout: 30_000 }); // greeting in
  await sleep(2500); // let panels finish painting before screenshots
}

const launcherRect = (page) => page.evaluate(() => { const b = document.querySelector("#cw-launch"); const r = b.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, shown: getComputedStyle(b).display !== "none" }; });
const winState = (page) => page.evaluate(() => {
  const w = document.querySelector("#cw-win"); if (!w) return null;
  const cs = getComputedStyle(w), r = w.getBoundingClientRect();
  return { open: w.classList.contains("open"), inert: w.inert, ariaHidden: w.getAttribute("aria-hidden"), opacity: +cs.opacity, transform: cs.transform, visibility: cs.visibility,
    running: w.getAnimations().length, x: r.x, y: r.y, w: r.width, h: r.height, vw: innerWidth, vh: innerHeight };
});
const labelState = (page) => page.evaluate(() => { const l = document.querySelector("#cw-label"); const cs = getComputedStyle(l); const r = l.getBoundingClientRect();
  return { opacity: +cs.opacity, pe: cs.pointerEvents, x: r.x, y: r.y, w: r.width, h: r.height, right: r.right, bottom: r.bottom }; });
const tab = (page, t) => page.click(`button.tab[data-tab="${t}"]`);
const waitIdle = (page, ms = 120_000) => page.waitForFunction(() => chatBusy === null, null, { timeout: ms });
const waitText = (page, ms = 90_000) => page.waitForFunction(() => chatMsgs.at(-1)?.state === "streaming" || chatMsgs.at(-1)?.state === "done", null, { timeout: ms });
const settle = () => sleep(400); // longer than the 220ms transition
const overlap = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
// Freeze the window's transition part-way so a mid-transition frame can be captured.
const freezeAt = (page, ms) => page.evaluate((ms) => document.querySelector("#cw-win").getAnimations().forEach((a) => { a.pause(); a.currentTime = ms; }), ms);
const unfreeze = (page) => page.evaluate(() => document.querySelector("#cw-win").getAnimations().forEach((a) => a.play()));

async function fixedWhileScrolling(page, name) {
  await page.evaluate(() => window.scrollTo(0, 0)); await sleep(200);
  const a = await launcherRect(page);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight)); await sleep(300);
  const b = await launcherRect(page);
  const scrolled = await page.evaluate(() => window.scrollY);
  const vp = await page.evaluate(() => ({ w: innerWidth, h: innerHeight, docW: document.documentElement.scrollWidth }));
  check(`${name}: launcher fixed while scrolling (scrolled ${Math.round(scrolled)}px)`, a.shown && scrolled > 200 && a.x === b.x && a.y === b.y, JSON.stringify(a));
  check(`${name}: launcher fully on screen, page not wider than the viewport`, a.x + a.w <= vp.w && a.y + a.h <= vp.h && vp.docW <= vp.w, JSON.stringify(vp));
}

async function signOutMidAnswer(page) {
  await page.evaluate(() => newChat());
  if (!(await page.evaluate(() => cwOpen))) { await page.click("#cw-launch"); await settle(); }
  await page.fill("#cw-win textarea", "Summarise the last seven days of weather at the estate.");
  await page.keyboard.press("Enter");
  await waitText(page);
  await page.evaluate(() => sb.auth.signOut());
  await page.waitForFunction(() => document.querySelector("#auth-view").classList.contains("on"));
  check("sign-out mid-answer clears chat state at once and closes the window", await page.evaluate(() => chatHistory.length === 0 && chatMsgs.length === 0 && chatBusy === null && !document.querySelector("#chatlog").textContent.trim() && !document.querySelector("#cw-win .cw-log").textContent.trim() && !document.querySelector("#cw-win").classList.contains("open") && document.querySelector("#cw-win").inert));
  await signIn(page, CUSTOMER_B2);
  await sleep(4000); // longer than the rest of the mocked stream
  const inherit = await page.evaluate(() => ({ history: chatHistory.length, nonGreeting: chatMsgs.filter((m) => !m.greeting).length,
    text: [...document.body.innerText.matchAll(/.{0,50}(Summarise the last seven days|Which block is driest right now).{0,30}/g)].map((m) => m[0]) }));
  check("next user on the same page inherits nothing", inherit.history === 0 && inherit.nonGreeting === 0 && inherit.text.length === 0, JSON.stringify(inherit));
}

// Safety net: a real request to the chat function is allowed only while
// `allowReal` is set (the one --real-question). Anything else is aborted and
// fails the run, so a broken mock can never spend real questions unnoticed.
// Page-level routes (the 413 case) take precedence over this one.
let allowReal = false, realAsked = 0, offlineNow = false;
async function guardChat(context) {
  await context.route("**/functions/v1/chat", (route) => {
    if (offlineNow) return route.abort("internetdisconnected"); // the offline test: never reaches the network anyway
    if (allowReal) { realAsked++; return route.continue(); }
    check("no unplanned real chat request", false, route.request().url());
    return route.abort("blockedbyclient");
  });
}

const executablePath = arg("chrome") ?? process.env.CHROME_PATH;
const browser = await chromium.launch(executablePath ? { executablePath, headless: true } : { channel: "chrome", headless: true });
try {
  // ── Operator, desktop ────────────────────────────────────────────────────
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await guardChat(ctx);
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("pageerror:", e.message));
  await open(page);
  check("window DOM not built before first open", await page.evaluate(() => !document.querySelector("#cw-win")));
  await signIn(page, OPERATOR);
  await shot(page, "01-desktop-vineyard-launcher");
  await fixedWhileScrolling(page, "vineyard");
  await tab(page, "winery"); await sleep(3000);
  await fixedWhileScrolling(page, "winery");
  await tab(page, "chat"); await sleep(300);
  check("launcher hidden on the Chat tab", !(await launcherRect(page)).shown);
  check("Chat tab keeps its suggestion chips", await page.evaluate(() => document.querySelectorAll("#chipPanel .chip-card").length > 0));
  check("Chat tab header carries the AI badge and the AI note", await page.evaluate(() => /AI/.test(document.querySelector(".chat-ttl .ai-badge").textContent) && /^AI-generated answers/.test(document.querySelector(".chat-note").textContent)));
  await shot(page, "02-desktop-chat-tab-ai-header");
  await tab(page, "vineyard"); await page.evaluate(() => window.scrollTo(0, 0));

  // Hover label.
  check("launcher aria-label says AI", /AI assistant/.test(await page.getAttribute("#cw-launch", "aria-label")));
  check("label hidden at rest", (await labelState(page)).opacity === 0);
  await page.hover("#cw-launch"); await settle();
  const lh = await labelState(page), lr = await launcherRect(page);
  check("hover shows the label to the left of the button", lh.opacity === 1 && lh.right <= lr.x && Math.abs(lh.y + lh.h / 2 - (lr.y + lr.h / 2)) < 12, JSON.stringify(lh));
  check("label never takes clicks", lh.pe === "none" && await page.evaluate(() => { const r = document.querySelector("#cw-label").getBoundingClientRect(); return document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)?.id !== "cw-label"; }));
  check("label is not a native title tooltip", (await page.getAttribute("#cw-launch", "title")) === null);
  await shot(page, "03-desktop-hover-label");

  // Open: animated, then settled; inert/aria-hidden only while closed.
  await page.click("#cw-launch");
  const w0 = await winState(page);
  check("open is animated (transition running at the start)", w0.open && w0.running > 0, JSON.stringify({ running: w0.running, opacity: w0.opacity }));
  await freezeAt(page, 90);
  const wMid = await winState(page);
  check("mid-open frame is part-way (fading and scaling from the corner)", wMid.opacity > 0.05 && wMid.opacity < 0.95 && wMid.transform !== "none", JSON.stringify({ opacity: wMid.opacity, transform: wMid.transform }));
  await shot(page, "04-desktop-open-mid-transition");
  await unfreeze(page); await settle();
  const w1 = await winState(page);
  check("open settles: opaque, untransformed, visible, not inert", w1.opacity === 1 && w1.transform === "none" && w1.visibility === "visible" && !w1.inert && w1.ariaHidden === null && w1.running === 0, JSON.stringify(w1));
  check("window bounded on desktop", w1.w === 400 && w1.h <= Math.min(620, w1.vh - 160) && w1.y > 0 && w1.x > w1.vw / 2);
  check("focus moves into the window's input", await page.evaluate(() => document.activeElement === document.querySelector("#cw-win textarea")));
  const lOpen = await labelState(page);
  check("label hidden while the window is open, so it never covers it", lOpen.opacity === 0, JSON.stringify({ opacity: lOpen.opacity, overlapsWindow: overlap(lOpen, w1) }));
  check("header shows the AI badge", await page.evaluate(() => document.querySelector("#cw-win .cw-ttl .ai-badge")?.textContent.startsWith("AI")));
  check("no starter prompts in the window", await page.evaluate(() => !document.querySelector("#cw-win .cw-start, #cw-win .cw-starters")));
  check("empty state shows the intro, not the greeting", await page.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-intro")).display !== "none" && /Answers are AI-generated/.test(document.querySelector("#cw-win .cw-intro").textContent) && !/Hi /.test(document.querySelector("#cw-win .cw-log").textContent)));
  check("AI note under the input", await page.evaluate(() => /^AI-generated answers from Mars Estate.s live data · check anything important against the dashboard/.test(document.querySelector("#cw-win .cw-meta").textContent)));
  check("page context chip kept", /Attached:/.test(await page.textContent("#cw-win .cw-ctx")));
  check("dashboard behind stays usable (panel controls outside the window take clicks)", await page.evaluate(() => {
    const w = document.querySelector("#cw-win").getBoundingClientRect();
    const b = [...document.querySelectorAll("#body-vineyard .rng button, #body-vineyard .p-ask")].find((x) => { const r = x.getBoundingClientRect(); return r.top > 80 && r.bottom < innerHeight && r.right < w.left; });
    if (!b) return false; const r = b.getBoundingClientRect(); return b.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)); }));
  await shot(page, "05-desktop-window-empty-state");

  // First message: the intro goes; the (mocked) stream survives minimise.
  await page.fill("#cw-win textarea", "Which block is driest right now?");
  await page.keyboard.press("Enter");
  check("intro disappears once the first message is sent", await page.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-intro")).display === "none"));
  await waitText(page);
  await page.mouse.move(200, 400);
  await page.keyboard.press("Escape");
  const wc0 = await winState(page);
  check("minimise is animated (transition running, still visible at the start)", !wc0.open && wc0.running > 0 && wc0.visibility === "visible", JSON.stringify({ running: wc0.running, visibility: wc0.visibility }));
  check("closed window is inert and aria-hidden immediately", wc0.inert && wc0.ariaHidden === "true");
  check("Esc returns focus to the launcher", await page.evaluate(() => document.activeElement === document.querySelector("#cw-launch")));
  await settle();
  const wc1 = await winState(page);
  check("minimise settles: transparent, hidden, no clicks", wc1.opacity === 0 && wc1.visibility === "hidden" && wc1.running === 0, JSON.stringify(wc1));
  check("keyboard focus on the launcher shows the label", (await labelState(page)).opacity === 1);
  check("closed window cannot take focus", await page.evaluate(() => { document.querySelector("#cw-win textarea").focus(); return document.activeElement !== document.querySelector("#cw-win textarea"); }));
  check("answer still streaming after minimise", await page.evaluate(() => chatBusy !== null));
  await waitIdle(page);
  check("answer committed while minimised", await page.evaluate(() => chatHistory.length >= 2 && chatMsgs.at(-1).state === "done"));
  check("unread dot on the launcher", await page.evaluate(() => !document.querySelector("#cw-dot").hidden && /new answer/.test(document.querySelector("#cw-launch").getAttribute("aria-label"))));
  await page.click("#cw-launch"); await settle();
  const ro = await page.evaluate(() => ({ dotHidden: document.querySelector("#cw-dot").hidden, ai: /Mars Telemetry AI/.test(document.querySelector("#cw-win .cw-log").textContent), answer: /mock answer/.test(document.querySelector("#cw-win .cw-log").textContent), log: document.querySelector("#cw-win .cw-log").textContent.slice(-300), last: chatMsgs.at(-1).text.slice(0, 80) }));
  check("reopen clears the dot and shows the answer, attributed to AI", ro.dotHidden && ro.ai && ro.answer, JSON.stringify(ro));
  // Enough content to scroll, then a draft and a scroll position to keep.
  await page.evaluate(async () => { for (let i = 0; i < 3; i++) await ask("filler question " + i, { surface: "widget" }); });
  const scrollable = await page.evaluate(() => { const l = document.querySelector("#cw-win .cw-log"); l.scrollTop = 40; l.dispatchEvent(new Event("scroll")); return l.scrollHeight - l.clientHeight > 40; });
  await page.fill("#cw-win textarea", "draft I have not sent");
  await page.click('#cw-win [data-cw="min"]'); await settle();
  await page.click("#cw-launch"); await settle();
  check("minimise/reopen keeps the unsent draft", (await page.inputValue("#cw-win textarea")) === "draft I have not sent");
  check("minimise/reopen keeps the scroll position", scrollable && await page.evaluate(() => document.querySelector("#cw-win .cw-log").scrollTop === 40), scrollable ? "" : "(log not scrollable)");

  // Rapid toggling never sticks mid-way.
  await page.evaluate(() => { for (let i = 0; i < 5; i++) document.querySelector("#cw-launch").click(); }); // open -> ends closed
  await settle();
  const r5 = await winState(page);
  check("rapid toggle x5 settles closed", !r5.open && r5.opacity === 0 && r5.visibility === "hidden" && r5.inert && r5.running === 0, JSON.stringify(r5));
  await page.click("#cw-launch"); await sleep(70); await page.click("#cw-launch"); await sleep(60); await page.click("#cw-launch"); // reversed twice mid-flight; ends open
  await settle();
  const r3 = await winState(page);
  check("reversing mid-transition settles open", r3.open && r3.opacity === 1 && r3.transform === "none" && r3.visibility === "visible" && !r3.inert, JSON.stringify(r3));

  // Reduced motion: instant.
  await page.click('#cw-win [data-cw="min"]'); await settle();
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.click("#cw-launch");
  const rm = await winState(page);
  check("reduced motion: opens instantly (no transition)", rm.open && rm.opacity === 1 && rm.transform === "none" && rm.running === 0, JSON.stringify(rm));
  await page.keyboard.press("Escape");
  const rmc = await winState(page);
  check("reduced motion: closes instantly", !rmc.open && rmc.visibility === "hidden" && rmc.running === 0, JSON.stringify(rmc));
  await page.emulateMedia({ reducedMotion: "no-preference" });

  // Continue in the Chat tab and back.
  await page.click("#cw-launch"); await settle();
  await page.click('#cw-win [data-cw="expand"]');
  check("expand goes to the Chat tab with the thread", await page.evaluate(() => state.tab === "chat" && /Which block is driest/.test(document.querySelector("#chatlog").textContent)));
  await page.fill("#chatin", "How does that compare with a week ago?");
  await page.click("#send");
  await waitIdle(page);
  await tab(page, "vineyard");
  await page.click("#cw-launch"); await settle();
  check("follow-up asked in the Chat tab appears in the window", await page.evaluate(() => /compare with a week ago/.test(document.querySelector("#cw-win .cw-log").textContent)));
  await page.click('#cw-win [data-cw="min"]'); await settle();

  // Ask about this.
  await page.click('.panel[data-panel-id="soilmoist"] .p-ask'); await settle();
  check("Ask about this: panel attached + question prefilled, nothing sent", await page.evaluate(() => /Soil moisture/.test(document.querySelector("#cw-win .cw-ctx").textContent) && /Soil moisture/.test(document.querySelector("#cw-win textarea").value) && chatBusy === null));
  await page.click('#cw-win [data-ctx="clear"]');
  check("context can be cleared", /Nothing attached/.test(await page.textContent("#cw-win .cw-ctx")));
  await page.click('#cw-win [data-ctx="add"]');

  // Error states on the real fetch path, served by routes (no real question).
  await page.evaluate(() => { window.__chatMock = "real"; });
  await page.route("**/functions/v1/chat", (route) => route.fulfill({ status: 413, contentType: "application/json", body: JSON.stringify({ code: "history_too_large", error: "This conversation has grown too long to continue. Start a new chat to keep going." }) }));
  await page.fill("#cw-win textarea", "test: 413");
  await page.keyboard.press("Enter");
  await waitIdle(page);
  check("413 shown with a New chat action", await page.evaluate(() => /grown too long/.test(document.querySelector("#cw-win .cw-log").textContent) && !!document.querySelector('#cw-win [data-act="new"]')));
  await page.unroute("**/functions/v1/chat");
  await ctx.setOffline(true); offlineNow = true;
  await page.fill("#cw-win textarea", "test: offline");
  await page.keyboard.press("Enter");
  await waitIdle(page);
  check("offline state with Retry", await page.evaluate(() => /offline/.test(document.querySelector("#cw-win .cw-log").textContent) && !!document.querySelector('#cw-win [data-act="retry"]')));
  await ctx.setOffline(false); offlineNow = false;
  await page.evaluate(() => { window.__chatMock = "stream"; });
  if (await page.$('#cw-win [data-act="retry"]')) { await page.click('#cw-win [data-act="retry"]'); await waitIdle(page); }
  check("Retry re-sends and replaces the failure", await page.evaluate(() => chatMsgs.at(-1).state === "done" && chatMsgs.filter((m) => m.text === "test: offline").length === 1));

  await page.emulateMedia({ media: "print" });
  check("launcher, label and window hidden in print", await page.evaluate(() => ["#cw-launch", "#cw-label", "#cw-win"].every((s) => getComputedStyle(document.querySelector(s)).display === "none")));
  await page.emulateMedia({ media: "screen" });

  // The one real question (operator, from the window).
  if (REAL) {
    await page.evaluate(() => { newChat(); window.__chatMock = "real"; });
    allowReal = true;
    await page.fill("#cw-win textarea", "What does the growing degree days chart show this season?");
    await page.keyboard.press("Enter");
    await waitIdle(page);
    check("real answer arrives in the window, attributed to AI", await page.evaluate(() => chatMsgs.at(-1).state === "done" && /Mars Telemetry AI/.test(document.querySelector("#cw-win .cw-log").textContent)));
    await page.evaluate(() => { document.querySelector("#cw-win .cw-log").scrollTop = 0; });
    await shot(page, "06-desktop-window-real-answer");
    allowReal = false;
    await page.evaluate(() => { window.__chatMock = "stream"; });
  }

  // Sign-out mid-answer (mocked stream), then B2 on the same page.
  await signOutMidAnswer(page);

  // ── Customer B2: role gating unchanged ───────────────────────────────────
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
  await page.click("#cw-launch"); await settle();
  await page.waitForFunction(() => /block B2/.test(document.querySelector("#cw-win .cw-ctx").textContent), null, { timeout: 10_000 }).catch(() => {});
  check("B2: context names only B2", /block B2 ·/.test(await page.textContent("#cw-win .cw-ctx")));
  check("B2: intro shown, no starters", await page.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-intro")).display !== "none" && !document.querySelector("#cw-win .cw-start")));
  await ctx.close();

  // ── Phone: B2, touch device (no hover) ───────────────────────────────────
  const pctx = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
  await guardChat(pctx);
  const phone = await pctx.newPage();
  await open(phone);
  await signIn(phone, CUSTOMER_B2);
  const peek0 = await phone.evaluate(() => document.querySelector("#cw-label").classList.contains("peek"));
  check("touch: label shown once on first appearance", peek0 && (await labelState(phone)).opacity === 1);
  await shot(phone, "07-phone-label-peek");
  await sleep(4000);
  check("touch: label goes away by itself", !(await phone.evaluate(() => document.querySelector("#cw-label").classList.contains("peek"))) && (await labelState(phone)).opacity === 0);
  await tab(phone, "winery"); await tab(phone, "vineyard"); await sleep(300);
  check("touch: shown only once per page session", !(await phone.evaluate(() => document.querySelector("#cw-label").classList.contains("peek"))));
  await fixedWhileScrolling(phone, "phone vineyard");
  await phone.evaluate(() => window.scrollTo(0, 400));
  await phone.tap("#cw-launch");
  const p0 = await winState(phone);
  check("phone: sheet slides (transform transition running, no fade)", p0.open && p0.running > 0 && p0.opacity === 1, JSON.stringify({ running: p0.running, opacity: p0.opacity }));
  await freezeAt(phone, 110);
  const pMid = await winState(phone);
  check("phone: mid-slide frame is part-way up", /matrix/.test(pMid.transform) && pMid.y > 101 && pMid.y < 844, JSON.stringify({ y: pMid.y, transform: pMid.transform }));
  await shot(phone, "08-phone-sheet-mid-slide");
  await unfreeze(phone); await settle();
  const p1 = await winState(phone);
  check("phone: bottom sheet, full width, ~88% height", p1.w === 390 && Math.abs(p1.y + p1.h - 844) < 2 && p1.h > 700 && p1.h < 760, JSON.stringify(p1));
  check("phone: launcher steps aside while open", !(await launcherRect(phone)).shown);
  check("phone: obvious close button", await phone.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-close-x")).display !== "none"));
  check("phone: intro in the empty sheet, no starters", await phone.evaluate(() => getComputedStyle(document.querySelector("#cw-win .cw-intro")).display !== "none" && !document.querySelector("#cw-win .cw-start")));
  await shot(phone, "09-phone-sheet-empty");
  await phone.fill("#cw-win textarea", "What's the current soil moisture in my block?");
  await phone.tap("#cw-win .send");
  await waitIdle(phone);
  await shot(phone, "10-phone-sheet-answer");
  await phone.tap('#cw-win [data-cw="min"]');
  const pc = await winState(phone);
  check("phone: sheet slides down on close", !pc.open && pc.running > 0, JSON.stringify({ running: pc.running }));
  await settle();
  check("phone: close returns to the page", !(await winState(phone)).open && (await launcherRect(phone)).shown);
  await pctx.close();

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
  await p2.click("#cw-launch"); await settle();
  await p2.fill("#cw-win textarea", "Which block is driest?");
  await p2.keyboard.press("Enter");
  await waitIdle(p2);
  await p2.click('#cw-win [data-act="flag"]');
  await shot(p2, "11-desktop-flag-notice");
  check("no text sent before the flag is confirmed", events.every((e) => !("question" in e) && !("answer" in e)), JSON.stringify(events.map((e) => e.event)));
  await p2.click('#cw-win [data-act="flag-send"]');
  await p2.waitForFunction(() => /Reported/.test(document.querySelector("#cw-win .cw-log").textContent));
  const flag = events.at(-1);
  check("flag carries question + answer text, nothing else does", flag.event === "flag_wrong" && /Which block is driest\?/.test(flag.question) && /18\.2%/.test(flag.answer) && events.slice(0, -1).every((e) => !("question" in e)), JSON.stringify(events.map((e) => e.event)));
  await ctx2.close();
} finally {
  await browser.close();
}
const bad = results.filter((r) => !r.ok).length;
console.log(`\n${results.length} checks, ${bad} failed; real chat requests sent: ${realAsked}`);
process.exit(bad ? 1 : 0);
