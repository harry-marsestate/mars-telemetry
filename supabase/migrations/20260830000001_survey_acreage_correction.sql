-- Acreage corrected to the Silverado Farming Company survey, confirmed by the
-- winery as authoritative. Supersedes BOTH the original seed values AND
-- InnoVint's block acreage (which the fruit panel briefly used as its own basis).
--   B1 3.7 -> 2.99   B2 2.2 -> 2.91   B3 1.4 -> 1.45   (estate 7.3 -> 7.35)
--
-- Deliberately NOT touched: blocks.planted (B1's '2009-2014' is separately
-- wrong and unresolved) and blocks.row_count (the survey's MRS-1A rows 1-27 /
-- MRS-1B rows 5-27 overlap almost entirely rather than partitioning, so they
-- are not trustworthy as distinct ranges -- flagged, not propagated).
update blocks set acres = 2.99 where block_id = 'B1';
update blocks set acres = 2.91 where block_id = 'B2';
update blocks set acres = 1.45 where block_id = 'B3';

-- B1's variety split per the survey's sub-block breakdown:
-- MRS-1A 1.12 + MRS-1B 0.98 = 2.10 Cab Sauv; MRS-1C 0.60 Cab Franc;
-- MRS-1D 0.29 Petit Verdot. Sums to 2.99, matching blocks.acres above.
update block_lots set acres = 2.10 where block_id='B1' and variety_key='cs';
update block_lots set acres = 0.60 where block_id='B1' and variety_key='cf';
update block_lots set acres = 0.29 where block_id='B1' and variety_key='pv';
update block_lots set acres = 2.91 where block_id='B2' and variety_key='cs';
update block_lots set acres = 1.45 where block_id='B3' and variety_key='cs';

-- labour_summary is a VIEW over blocks.acres (confirmed pg_class.relkind='v'),
-- so cost_per_acre reflects this immediately -- no dbt run required.
