"""Pydantic contracts for the InnoVint API responses this ingestion consumes.

Every model uses extra="forbid": a field InnoVint adds, renames, or removes
should raise a validation error during ingestion, not silently pass through
or get dropped.

InnoVint publishes a full OpenAPI 3.1 spec, contrary to what this docstring
claimed until 2026-08-30: GET /api/v1/schema (YAML), /api/v1/docs (rendered),
and /openapi.json (a separate "MAKE Internal APIs" spec). All three are
readable with the ordinary access token.

The Lot/Analysis/Vessel models below predate that discovery and were
transcribed from observed responses; the GrowerReceipt/Varietal models were
derived from the spec's DECLARED nullability. Prefer the spec for anything
new -- sample-derived nullability is weak evidence (the `component: Any`
workaround below exists precisely because a sample-derived guess had nothing
to go on).
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

    NOT interchangeable with FloatUnit below: the spec declares FloatUnit's
    value non-nullable, while this model's Optional reflects genuine
    uncertainty about vessel types never sampled. Do not merge them.

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


# ── /growerReceipts/{vintage} ────────────────────────────────────────────

# Spec-declared enum, all 17 values. Note four spellings of tons, plus
# weight AND volume units sharing one enum -- a volume unit arriving on a
# fruit weight is a real data error, handled loudly in weights.py.
FloatUnitName = Literal[
    "gal", "gallons", "hl", "liters", "litres", "pg", "PG", "kg", "lbs",
    "tonne", "tons", "gallon", "hL", "L", "kilograms", "tonnes", "ton",
]


class FloatUnit(StrictModel):
    """Spec: both `value` and `unit` are required and non-nullable."""

    value: float
    unit: FloatUnitName


class GrowerReceiptAnalysis(StrictModel):
    """Empty ([]) on all 6 rows live, but the spec declares a real shape, so
    it is modelled properly rather than as Any -- brix/pH at receipt could
    legitimately land here in a future harvest."""

    analysis_type: str = Field(alias="analysisType")
    unit: str
    value: float


class GrowerReceiptAdjustment(StrictModel):
    provision: str
    amount: float


class GrowerReceipt(StrictModel):
    """Every field below is spec-required and none is spec-nullable."""

    id: str
    action_id: str = Field(alias="actionId")
    lot_id: str = Field(alias="lotId")
    grower_id: str = Field(alias="growerId")
    block_id: str = Field(alias="blockId")
    vineyard_id: str = Field(alias="vineyardId")
    varietal_id: str = Field(alias="varietalId")
    appellation_id: str = Field(alias="appellationId")
    vintage: int
    weigh_tag_number: str = Field(alias="weighTagNumber")
    receipt_date: datetime = Field(alias="receiptDate")
    analyses: list[GrowerReceiptAnalysis] = Field(default_factory=list)
    total_weight: FloatUnit = Field(alias="totalWeight")
    contract_cost: float = Field(alias="contractCost")
    contract_cost_per_unit: float = Field(alias="contractCostPerUnit")
    adjustments: list[GrowerReceiptAdjustment] = Field(default_factory=list)
    net_cost: float = Field(alias="netCost")
    net_cost_per_unit: float = Field(alias="netCostPerUnit")


class GrowerReceiptEnvelopeItem(StrictModel):
    data: GrowerReceipt
    relationships: dict[str, str | None] = Field(default_factory=dict)


class GrowerReceiptsResponse(StrictModel):
    results: list[GrowerReceiptEnvelopeItem]
    pagination: Pagination


# ── /varietals (GLOBAL - not winery-scoped) ──────────────────────────────

class VarietalRelationships(StrictModel):
    """`source` is an int here, unlike the `dict[str, str | None]` shape every
    winery-scoped envelope uses. Modelled separately rather than widening the
    shared type -- under extra="forbid" a wrong type fails the whole response.
    """

    source: int


class Varietal(StrictModel):
    """All four fields spec-required and non-nullable."""

    id: str
    internal_id: int = Field(alias="internalId")
    color: str
    name: str


class VarietalEnvelopeItem(StrictModel):
    data: Varietal
    relationships: VarietalRelationships


class VarietalsResponse(StrictModel):
    results: list[VarietalEnvelopeItem]
    pagination: Pagination
