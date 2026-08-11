"""Thin InnoVint API client. Pagination, raw-JSON landing, and pydantic
validation all happen here, so asset code only ever deals with validated
Python objects and never touches HTTP or raw bytes directly.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator

import httpx

from .contracts import (
    AnalysesResponse,
    BlockComponentsResponse,
    InnoVintAnalysis,
    InnoVintVessel,
    VesselsResponse,
)
from .raw_landing import land_raw

BASE_URL = "https://sutter.innovint.us/api/v1"

# ~100 calls per run (47 lots x analyses + 47 x blockComponents + a few
# vessel pages). No documented InnoVint rate limit was found during the
# data inventory; this is just a polite default for a scheduled job
# hitting a third party, not a response to any observed throttling.
REQUEST_PAUSE_SECONDS = 0.1


class InnoVintClient:
    def __init__(self, token: str, winery_id: str, run_stamp: str):
        self._winery_id = winery_id
        self._run_stamp = run_stamp
        self._http = httpx.Client(
            headers={"Authorization": f"Access-Token {token}"},
            timeout=30.0,
        )

    def close(self) -> None:
        self._http.close()

    def _get(self, url: str, category: str, key: str) -> bytes:
        resp = self._http.get(url)
        resp.raise_for_status()
        land_raw(self._run_stamp, category, key, resp.content)
        time.sleep(REQUEST_PAUSE_SECONDS)
        return resp.content

    def list_lot_ids(self) -> list[str]:
        ids: list[str] = []
        url = f"{BASE_URL}/wineries/{self._winery_id}/lots?limit=100"
        page = 0
        while url:
            raw = self._get(url, "lots", f"page{page}")
            payload = json.loads(raw)
            ids.extend(r["data"]["id"] for r in payload["results"])
            url = payload["pagination"]["next"]
            page += 1
        return ids

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
        raw = self._get(url, "block_components", lot_id)
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
