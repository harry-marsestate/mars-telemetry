import "@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "@supabase/server";

// Called by an admin's own browser session to resolve pending users' real
// emails (auth.users, never client-queryable) for the approval queue.
// ctx.supabase is RLS-scoped to the caller's own JWT -- used ONLY to verify
// is_admin before ctx.supabaseAdmin (bypasses RLS entirely) ever touches
// the Admin API. Skipping that check would let any authenticated caller
// harvest every pending user's email.
//
// Deliberately NOT the "always return 200" pattern notify-admin-approval
// uses -- that rule exists because Database Webhooks retry aggressively on
// non-200. This function is called directly by the admin's own browser, no
// webhook retry semantics involved, and the caller genuinely needs to know
// if something failed rather than silently render an empty queue.
export default {
  fetch: withSupabase({ auth: ["user"] }, async (req, ctx) => {
    try {
      const { data: isAdmin, error: adminErr } = await ctx.supabase.rpc('is_admin_user');
      if (adminErr || !isAdmin) {
        return Response.json({ error: 'Forbidden' }, { status: 403 });
      }

      const { ids } = await req.json();
      if (!Array.isArray(ids) || ids.length === 0) {
        return Response.json({ emails: {} }, { status: 200 });
      }

      // No batch getUsersByIds in the Admin API -- N parallel calls, not
      // sequential, sized fine for an approval queue.
      const results = await Promise.all(ids.map(async (id) => {
        const { data, error } = await ctx.supabaseAdmin.auth.admin.getUserById(id);
        return { id, email: error ? null : (data?.user?.email ?? null) };
      }));

      const emails = {};
      for (const r of results) emails[r.id] = r.email;

      return Response.json({ emails }, { status: 200 });
    } catch (err) {
      console.error('admin-pending-emails: unexpected error', err);
      return Response.json({ error: 'unexpected error' }, { status: 500 });
    }
  }),
};
