-- blocks.innovint_block_id: confirmed dead, re-grepped the whole repo
-- fresh (not trusting the prior check). Only remaining references are
-- historical migrations, docs/SECURITY.md's record, and
-- ingestion/innovint/db.py's own comment stating it does NOT read this
-- column. The sole blocker (per docs/SECURITY.md) was
-- lot_analyses.block_id's stale column comment naming it -- reissued
-- below, in the same migration as the drop, describing the actual
-- current resolution path (block_innovint_map / resolve_block_id()).
comment on column lot_analyses.block_id is
  'Best-effort resolution via block_innovint_map (time-scoped; see resolve_block_id() in ingestion/innovint/db.py). NULL for unresolved/multi-block-blend lots, or a vintage outside any mapped window; do not treat absence as an error.';

alter table blocks drop column innovint_block_id;
