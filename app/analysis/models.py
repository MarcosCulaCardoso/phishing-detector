from pydantic import BaseModel, Field

from app.schemas import Evidence, EvidenceKind, Modality, SecurityReport


class RuleHit(BaseModel):
    """One rule that fired. Points can't be added without evidence explaining them."""

    rule: str
    points: int = Field(gt=0)
    evidence: list[Evidence] = Field(min_length=1)


class AnalysisResult(BaseModel):
    hits: list[RuleHit] = Field(default_factory=list)
    raw_score: int
    report: SecurityReport


def observed(modality: Modality, statement: str, source: str) -> Evidence:
    return Evidence(kind=EvidenceKind.OBSERVED, modality=modality,
                    statement=statement, source=source)


def assessed(modality: Modality, statement: str, source: str) -> Evidence:
    return Evidence(kind=EvidenceKind.ASSESSMENT, modality=modality,
                    statement=statement, source=source)
