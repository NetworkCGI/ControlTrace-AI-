from pydantic import BaseModel
from typing import List


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DashboardSummary(BaseModel):
    compliance_score: float
    passed_controls: int
    failed_controls: int
    open_findings: int
    latest_result_summary: str | None = None


class FindingOut(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str


class ControlResultOut(BaseModel):
    id: str
    status: str
    score: float
    result_summary: str


class UploadResponse(BaseModel):
    evidence_item_id: str
    parsed_rows: int
    evaluation_status: str
    findings_created: int
