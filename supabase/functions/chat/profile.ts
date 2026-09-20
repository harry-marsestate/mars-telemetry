// Accept only the verified withSupabase userClaims, never request JSON.
// Missing identity must never become an unfiltered admin-visible query.
// deno-lint-ignore no-explicit-any
export async function callerProfile(supabase: any, claims: { id: string } | null | undefined) {
  if (!claims?.id) return { data: null, error: null };
  return await supabase.from("user_profiles").select("first_name, last_name")
    .eq("id", claims.id).maybeSingle();
}

export function resolveDisplayName(role: string, firstName: string | null, lastName: string | null): string | null {
  if (!firstName) return null;
  return role === "operator" ? firstName : (lastName ? `${firstName} ${lastName}` : firstName);
}
