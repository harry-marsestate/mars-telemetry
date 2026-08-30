"""Thin InnoVint API client. Pagination, raw-JSON landing, and pydantic
validation all happen here, so asset code only ever deals with validated
Python objects and never touches HTTP or raw bytes directly.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import httpx

from .contracts import (
    AnalysesResponse,
    BlockComponentsResponse,
    GrowerReceipt,
    GrowerReceiptsResponse,
    InnoVintAnalysis,
    InnoVintVessel,
    Lot,
    LotsResponse,
    Pagination,
    VarietalsResponse,
    VesselsResponse,
)
from .raw_landing import land_raw

BASE_URL = "https://sutter.innovint.us/api/v1"

# ~100 calls per run (47 lots x analyses + 47 x blockComponents + a few
# vessel pages, plus ~8 growerReceipts vintages and 1 varietals lookup).
# No documented InnoVint rate limit was found during the
# data inventory; this is just a polite default for a scheduled job
# hitting a third party, not a response to any observed throttling.
REQUEST_PAUSE_SECONDS = 0.1

# Cap on ids per `idIn` query, to keep the URL comfortably short. Only 2
# distinct varietals exist across all real receipts today; this is headroom.
VARIETAL_ID_CHUNK = 50


class InnoVintClient:
    def __init__(self, token: str, winery_id: str, run_stamp: str):
        self._winery_id = winery_id
        self._run_stamp = run_stamp
        self._http = httpx.Client(
            headers={"Authorization": f"Access-Token {token}"},
            timeout=30.0,
        )
        # Populated by fetch_block_components when it swallows a 404 --
        # see that method's docstring. Read by callers after a run for
        # logging/metadata; not used for any control flow here.
        self.dangling_lot_refs: set[str] = set()

    def close(self) -> None:
        self._http.close()

    def _get(self, url: str, category: str, key: str) -> bytes:
        resp = self._http.get(url)
        resp.raise_for_status()
        land_raw(self._run_stamp, category, key, resp.content)
        time.sleep(REQUEST_PAUSE_SECONDS)
        return resp.content

    def list_lots(self) -> list[Lot]:
        lots: list[Lot] = []
        url = f"{BASE_URL}/wineries/{self._winery_id}/lots?limit=100"
        page = 0
        while url:
            raw = self._get(url, "lots", f"page{page}")
            parsed = LotsResponse.model_validate_json(raw)
            lots.extend(item.data for item in parsed.results)
            url = parsed.pagination.next
            page += 1
        return lots

    def fetch_analyses(self, lot_id: str) -> Iterator[InnoVintAnalysis]:
        url = f"{BASE_URL}/wineries/{self._winery_id}/lots/{lot_id}/analyses?limit=50"
        page = 0
        while url:
            raw = self._get(url, "analyses", f"{lot_id}__page{page}")
            parsed = AnalysesResponse.model_validate_json(raw)
            for item in parsed.results:
                yield item.data
            url = parsed.pagination.next
            page += 1

    def fetch_block_components(self, lot_id: str) -> BlockComponentsResponse:
        url = f"{BASE_URL}/wineries/{self._winery_id}/lots/{lot_id}/blockComponents"
        try:
            raw = self._get(url, "block_components", lot_id)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # Confirmed live: a vessel's current lotId can point to a
                # lot that doesn't exist at all -- not in /lots, 404s on a
                # direct /lots/{id} fetch too. Same class of
                # dangling-reference issue already documented for
                # lots.bondId in docs/SECURITY.md, now seen on
                # vessels.lotId. Treated as "no resolvable block
                # components" rather than a fatal error; tracked in
                # dangling_lot_refs so it stays visible rather than
                # blending silently into the ordinary
                # multi-block/zero-component null cases.
                self.dangling_lot_refs.add(lot_id)
                return BlockComponentsResponse(
                    results=[], pagination=Pagination(count=0, next=None, previous=None)
                )
            raise
        return BlockComponentsResponse.model_validate_json(raw)

    def fetch_vessels(self) -> Iterator[InnoVintVessel]:
        url = f"{BASE_URL}/wineries/{self._winery_id}/vessels?limit=100"
        page = 0
        while url:
            raw = self._get(url, "vessels", f"page{page}")
            parsed = VesselsResponse.model_validate_json(raw)
            for item in parsed.results:
                yield item.data
            url = parsed.pagination.next
            page += 1

    def fetch_grower_receipts(self, vintage: int) -> list[GrowerReceipt]:
        """Fruit intake receipts for one vintage.

        Returns a list, not an iterator, deliberately: the caller reconciles
        deletions by comparing the COMPLETE per-vintage payload against what is
        already stored, and a partially-consumed iterator would make an empty or
        truncated result indistinguishable from "this vintage genuinely has no
        receipts" -- which would then delete real rows.

        This endpoint exposes no `deleted` flag and no `state` filter, unlike
        /actions/receiveFruitActions. Reconciliation is the only way to detect a
        deleted receipt.
        """
        receipts: list[GrowerReceipt] = []
        url = f"{BASE_URL}/wineries/{self._winery_id}/growerReceipts/{vintage}?limit=100"
        page = 0
        while url:
            raw = self._get(url, "grower_receipts", f"{vintage}__page{page}")
            parsed = GrowerReceiptsResponse.model_validate_json(raw)
            receipts.extend(item.data for item in parsed.results)
            url = parsed.pagination.next
            page += 1
        return receipts

    def fetch_varietal_names(self, varietal_ids: set[str]) -> dict[str, str]:
        """varietalId -> display name, for the ids actually referenced.

        /varietals is GLOBAL, not winery-scoped -- no wineryId in the path (the
        one method here that doesn't follow that pattern; it's InnoVint's shared
        varietal catalogue, confirmed against /api/v1/schema). Filtered with the
        spec's `idIn` parameter rather than paging the whole catalogue or making
        one request per id.

        Sorted before chunking so the raw-landing filenames are stable across
        runs with identical inputs.
        """
        if not varietal_ids:
            return {}
        names: dict[str, str] = {}
        ordered = sorted(varietal_ids)
        for start in range(0, len(ordered), VARIETAL_ID_CHUNK):
            chunk = ordered[start : start + VARIETAL_ID_CHUNK]
            url = f"{BASE_URL}/varietals?idIn={','.join(chunk)}&limit=100"
            page = 0
            while url:
                raw = self._get(
                    url, "varietals", f"chunk{start // VARIETAL_ID_CHUNK}__page{page}"
                )
                parsed = VarietalsResponse.model_validate_json(raw)
                for item in parsed.results:
                    names[item.data.id] = item.data.name
                url = parsed.pagination.next
                page += 1
        return names
