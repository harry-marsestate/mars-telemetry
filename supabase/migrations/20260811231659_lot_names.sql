-- Captures InnoVint's lot name/code, needed to redesign the ferm/tanks
-- winery panels around real data. Both were already present in every
-- /lots API response the ingestion fetches (list_lot_ids), but silently
-- discarded -- this costs zero new InnoVint API calls, just stops
-- throwing away data already in hand. Nullable: not every lot_analyses/
-- vessels row will have a resolvable lot at ingestion time (e.g. the
-- dangling vessels.current_lot_id references already found and handled
-- in the ingestion -- see client.py's fetch_block_components).
alter table lot_analyses add column lot_name text, add column lot_code text;
alter table vessels add column current_lot_name text, add column current_lot_code text;
