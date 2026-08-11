-- Links local vineyard blocks to their InnoVint block record, so InnoVint
-- lot/block/vessel data can eventually be queried and cross-referenced
-- against local block_id. Nullable + no default: the correspondence
-- between local blocks and InnoVint's block records isn't automatic (name/
-- acreage/planted-year don't line up cleanly - see investigation prior to
-- this migration) and needs to be populated by hand per block.
alter table blocks add column innovint_block_id text;
