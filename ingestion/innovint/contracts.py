"""Pydantic contracts for the InnoVint API responses this ingestion consumes.

Every model uses extra="forbid": a field InnoVint adds, renames, or removes
should raise a validation error during ingestion, not silently pass through
or get dropped. Shapes below are transcribed directly from the real
responses pulled during the InnoVint data inventory (GET
/wineries/{wineryId}/lots/{lotId}/analyses and GET
/wineries/{wineryId}/vessels against wnry_2PW0KJ93L726WKKG54OQE1RY), not
guessed from a spec -- InnoVint's own API docs for this resource set were
not discoverable (see docs/SECURITY.md and the InnoVint data inventory
findings).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# ── Shared envelope shapes ──────────────────────────────────────────────

class Pagination(StrictModel):
    count: int
    next: str | None = None
    previous: str | None = None


class OwnerTag(StrictModel):
    id: int
    public_id: str = Field(alias="publicId")
    internal_id: int = Field(alias="internalId")
    name: str


class Access(StrictModel):
    global_access: bool = Field(alias="globalAccess")
    owner_tags: list[OwnerTag] = Field(alias="ownerTags")


class Measurement(StrictModel):
    """{value, unit} pairs used for capacity/volume/weight/fruitWeight etc.

    value is optional even though every sample we pulled had a number --
    InnoVint returns 0.0 rather than omitting the field for "no data" in
    every case observed, but nothing in the inventory confirmed value can
    never be null for a vessel type we didn't sample (KEG/STEEL_DRUM
    capacity, specifically). Defaulting to Optional here is the safer
    read of evidence we don't fully have, not a guess either way.
    """

    value: float | None = None
    unit: str


# ── /lots ────────────────────────────────────────────────────────────────

class BottlesOnHand(StrictModel):
    cases: float
    bottles: float


class Lot(StrictModel):
    """Only id/name/code are consumed by this ingestion today (see
    list_lots() in client.py). Every other field must still be modeled --
    extra="forbid" means an unrecognized field fails the whole response,
    not just the field nobody reads. Fields not used downstream (stage,
    lot_type, lot_style, tax_class, color) are typed permissively (plain
    str, not Literal) rather than enumerated against today's observed
    values -- over-constraining a field nothing depends on adds fragility
    without benefiting anything built against it. Contrast with
    VesselType/analysis fields above, which back real ingestion logic and
    are deliberately strict.
    """

    id: str
    internal_id: int = Field(alias="internalId")
    access: Access
    archived: bool
    bond_id: str | None = Field(default=None, alias="bondId")
    bottles_on_hand: BottlesOnHand = Field(alias="bottlesOnHand")
    code: str
    color: str | None = None
    expected_yield: float | None = Field(default=None, alias="expectedYield")
    fruit_weight: Measurement = Field(alias="fruitWeight")
    lot_style: str = Field(alias="lotStyle")
    lot_type: str = Field(alias="lotType")
    name: str
    stage: str
    tags: list[Any] = Field(default_factory=list)
    tax_class: str = Field(alias="taxClass")
    volume: Measurement | None = None
    weight: Measurement | None = None


class LotEnvelopeItem(StrictModel):
    data: Lot
    relationships: dict[str, str | None] = Field(default_factory=dict)


class LotsResponse(StrictModel):
    results: list[LotEnvelopeItem]
    pagination: Pagination


# ── /lots/{lotId}/analyses ──────────────────────────────────────────────

class AnalysisType(StrictModel):
    name: str
    abbreviation: str  # seen empty string "" for Brix, not always populated
    slug: str


class AnalysisUnit(StrictModel):
    name: str
    unit: str


class InnoVintAnalysis(StrictModel):
    id: str
    analysis_type: AnalysisType = Field(alias="analysisType")
    # Always null in every one of the 1,411 real records pulled during the
    # inventory. True populated shape is unknown -- kept as Any rather than
    # guessing a structure and having extra="forbid" reject real data the
    # moment a lot with a populated component shows up.
    component: Any | None = None
    deleted: bool
    lot_id: str = Field(alias="lotId")
    recorded_at: datetime = Field(alias="recordedAt")
    skipped: bool
    unit: AnalysisUnit
    # Optional defensively: every sampled record had skipped=false and a
    # real value, but skipped=true records (never observed) may carry a
    # null value.
    value: float | None = None
    vessel_id: str | None = Field(default=None, alias="vesselId")
    action_id: str = Field(alias="actionId")


class AnalysisEnvelopeItem(StrictModel):
    data: InnoVintAnalysis
    relationships: dict[str, str | None] = Field(default_factory=dict)


class AnalysesResponse(StrictModel):
    results: list[AnalysisEnvelopeItem]
    pagination: Pagination


# ── /lots/{lotId}/blockComponents ───────────────────────────────────────

class NamedRef(StrictModel):
    id: str
    name: str


class BlockComponent(StrictModel):
    block: NamedRef
    varietal: NamedRef
    vineyard: NamedRef
    appellation: NamedRef
    vintage: int
    percentage: float


class BlockComponentEnvelopeItem(StrictModel):
    data: BlockComponent
    relationships: dict[str, str | None] = Field(default_factory=dict)


class BlockComponentsResponse(StrictModel):
    results: list[BlockComponentEnvelopeItem]
    pagination: Pagination


# ── /vessels ─────────────────────────────────────────────────────────────

# Literal, not str: the inventory saw exactly these four values (151
# BARREL, 78 TANK, 11 KEG, 1 STEEL_DRUM). A fifth value showing up should
# fail ingestion loudly rather than land as an unrecognized vessel_type in
# the vessels table.
VesselType = Literal["TANK", "BARREL", "KEG", "STEEL_DRUM"]


class InnoVintVessel(StrictModel):
    id: str
    internal_id: int = Field(alias="internalId")
    capacity: Measurement | None = None
    code: str | None = None
    color: str | None = None  # seen 'N/A' as a literal string, not absent
    vessel_type: VesselType = Field(alias="vesselType")
    lot_id: str | None = Field(default=None, alias="lotId")
    volume: Measurement | None = None
    weight: Measurement | None = None
    archived: bool
    access: Access


class VesselEnvelopeItem(StrictModel):
    data: InnoVintVessel
    relationships: dict[str, str | None] = Field(default_factory=dict)


class VesselsResponse(StrictModel):
    results: list[VesselEnvelopeItem]
    pagination: Pagination
