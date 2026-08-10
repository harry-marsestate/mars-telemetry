// Follow this setup guide to integrate the Deno language server with your editor:
// https://deno.land/manual/getting_started/setup_your_environment

import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";

// Called by the user_profiles UPDATE Database Webhook (dashboard-configured,
// filtered to confirmed_at is not null). Server-to-server only -- auth is
// restricted to the secret key, never publishable.
export default {
  fetch: withSupabase({ auth: ["secret"] }, async (req, ctx) => {
    try {
      const payload = await req.json();
      const { type, table, record, old_record } = payload ?? {};

      // Don't fully trust the dashboard filter alone: confirm this is
      // actually the event we think it is, and independently re-check the
      // same null -> not-null transition the on_auth_user_confirmed
      // trigger guards on.
      if (type !== "UPDATE" || table !== "user_profiles") {
        return Response.json({ ok: true, skipped: "not a user_profiles UPDATE" }, { status: 200 });
      }
      if (!(old_record?.confirmed_at == null && record?.confirmed_at != null)) {
        return Response.json({ ok: true, skipped: "not a confirmation transition" }, { status: 200 });
      }

      // user_profiles has no email column -- it lives on auth.users, so it
      // has to be looked up via the admin API, not the webhook payload.
      const { data: userData, error: userErr } = await ctx.supabaseAdmin.auth.admin.getUserById(record.id);
      const newUserEmail = userData?.user?.email;
      if (userErr || !newUserEmail) {
        console.error("notify-admin-approval: could not resolve user email", record.id, userErr);
        return Response.json({ ok: false, reason: "user lookup failed" }, { status: 200 });
      }

      const resendApiKey = Deno.env.get("RESEND_API_KEY");
      const adminEmail = Deno.env.get("ADMIN_NOTIFY_EMAIL");
      const fromEmail = Deno.env.get("RESEND_FROM_EMAIL");
      // TODO: currently set to http://localhost:3000/index.html for local
      // testing -- no real deployed URL yet. Update this secret
      // (supabase secrets set APPROVAL_QUEUE_URL=...) once one exists, or
      // approval emails will link to a dead local address.
      const approvalQueueUrl = Deno.env.get("APPROVAL_QUEUE_URL");

      if (!resendApiKey || !adminEmail || !fromEmail) {
        console.error("notify-admin-approval: missing RESEND_API_KEY, ADMIN_NOTIFY_EMAIL, or RESEND_FROM_EMAIL secret");
        return Response.json({ ok: false, reason: "missing config" }, { status: 200 });
      }

      const resendResp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: fromEmail,
          to: adminEmail,
          subject: `New account pending approval: ${newUserEmail}`,
          html:
            `<p><strong>${newUserEmail}</strong> confirmed their email and is waiting for approval.</p>` +
            (approvalQueueUrl ? `<p><a href="${approvalQueueUrl}">Open the approval queue</a></p>` : ""),
        }),
      });

      if (!resendResp.ok) {
        console.error("notify-admin-approval: Resend call failed", resendResp.status, await resendResp.text());
        return Response.json({ ok: false, reason: "resend failed" }, { status: 200 });
      }

      return Response.json({ ok: true }, { status: 200 });
    } catch (err) {
      // Catch-all: whatever goes wrong -- bad payload, admin API throwing,
      // network error calling Resend -- this must still return 200.
      // Supabase Database Webhooks retry aggressively on non-200 responses,
      // and the signup/confirmation flow that triggered this must never be
      // blocked or retry-stormed by a flaky email step.
      console.error("notify-admin-approval: unexpected error", err);
      return Response.json({ ok: false, reason: "unexpected error" }, { status: 200 });
    }
  }),
};

/* To invoke locally:

  1. Run `supabase start` (see: https://supabase.com/docs/reference/cli/supabase-start)
  2. Make an HTTP request:

  curl -i --location --request POST 'http://127.0.0.1:54321/functions/v1/notify-admin-approval' \
    --header 'apiKey: <service_role key>' \
    --header 'Content-Type: application/json' \
    --data '{"type":"UPDATE","table":"user_profiles","record":{"id":"...","confirmed_at":"2026-08-10T00:00:00Z"},"old_record":{"id":"...","confirmed_at":null}}'

*/
