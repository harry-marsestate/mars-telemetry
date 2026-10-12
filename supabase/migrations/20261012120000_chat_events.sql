-- chat_events: how the in-app chat is used, and answers users mark as wrong
-- (docs/SECURITY.md, "Floating chat launcher").
--
-- Nothing recorded in-app chat usage before this: the chat Edge Function logs
-- token counts only, and agent_api_key_calls covers MCP keys, not the app.
--
-- One row per event, written by the browser as the signed-in user:
--   open        the floating chat window was opened
--   ask         a question was sent (surface says from where)
--   thumb_up / thumb_down   a rating on one answer
--   flag_wrong  "This was wrong" on one answer
-- No question or answer text is ever stored EXCEPT on flag_wrong, where the
-- UI tells the user, at that moment and before they confirm, that their
-- question and the answer will be sent to the estate team. A CHECK makes that
-- structural rather than a client promise.
--
-- Access:
--   - Insert: any APPROVED user (operator or customer), own rows only.
--     user_id is not in the column grant, so the client cannot set it; it
--     defaults to auth.uid() and the policy re-checks it.
--   - Read: operators only. Customers cannot read rows back, not even their
--     own: the text on a flag is the estate's review queue, not a user log.
--   - No update or delete for anyone through the API.
-- Not exposed to mcp_reader or the MCP gateway (no grant).
create table public.chat_events (
  id         bigint generated always as identity primary key,
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  surface    text not null check (surface in ('widget', 'tab')),
  event      text not null check (event in ('open', 'ask', 'thumb_up', 'thumb_down', 'flag_wrong')),
  -- Which answer a rating/flag is about: the 0-based count of questions
  -- asked before it in the conversation.
  turn_index integer check (turn_index between 0 and 1000),
  -- Dashboard panel the question came from ("Ask about this"); an id from
  -- the dashboard's own PANELS list, never free text.
  panel_id   text check (panel_id ~ '^[a-z0-9_]{1,32}$'),
  question   text check (char_length(question) <= 4100),
  answer     text check (char_length(answer) <= 40000),
  constraint chat_events_text_only_on_flag
    check (event = 'flag_wrong' or (question is null and answer is null))
);

create index chat_events_created_at on public.chat_events (created_at desc);
create index chat_events_flags on public.chat_events (created_at desc) where event = 'flag_wrong';

alter table public.chat_events enable row level security;

revoke all on public.chat_events from anon, authenticated;
grant insert (surface, event, turn_index, panel_id, question, answer) on public.chat_events to authenticated;
grant select on public.chat_events to authenticated;

create policy chat_events_insert_own on public.chat_events
  for insert to authenticated
  with check (user_id = auth.uid() and public.current_role_name() in ('operator', 'customer'));

create policy chat_events_operator_read on public.chat_events
  for select to authenticated
  using (public.current_role_name() = 'operator');
