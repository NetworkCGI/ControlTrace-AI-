import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Text, Numeric, Integer
from sqlalchemy.orm import relationship
from .database import Base


def uuid_str() -> str:
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=uuid_str)
    name = Column(String(255), nullable=False)
    industry = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(50), nullable=False, default="org_admin")  # org_admin | auditor | viewer
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String, primary_key=True, default=uuid_str)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)


class Framework(Base):
    __tablename__ = "frameworks"
    id = Column(String, primary_key=True, default=uuid_str)
    name = Column(String(255), unique=True, nullable=False, index=True)
    version = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    category = Column(String(120), nullable=True)  # e.g. Federal, Healthcare, Financial, Privacy, General Security

    controls = relationship("Control", back_populates="framework", cascade="all, delete")


class Control(Base):
    __tablename__ = "controls"
    id = Column(String, primary_key=True, default=uuid_str)
    framework_id = Column(String, ForeignKey("frameworks.id"), nullable=True)
    control_code = Column(String(100), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(30), nullable=False, default="high")
    category = Column(String(100), nullable=True)

    framework = relationship("Framework", back_populates="controls")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    evidence_file_id = Column(String, ForeignKey("evidence_files.id"), nullable=False)
    evidence_type = Column(String(100), nullable=False, default="mfa_status_csv")
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(30), nullable=False, default="active")

    normalized_records = relationship("EvidenceNormalizedRecord", back_populates="evidence_item", cascade="all, delete-orphan")


class EvidenceNormalizedRecord(Base):
    __tablename__ = "evidence_normalized_records"
    id = Column(String, primary_key=True, default=uuid_str)
    evidence_item_id = Column(String, ForeignKey("evidence_items.id"), nullable=False)
    subject_identifier = Column(String(255), nullable=False)
    mfa_enabled = Column(Boolean, nullable=False)
    is_admin = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    evidence_item = relationship("EvidenceItem", back_populates="normalized_records")


class ControlResult(Base):
    __tablename__ = "control_results"
    id = Column(String, primary_key=True, default=uuid_str)
    control_id = Column(String, ForeignKey("controls.id"), nullable=False)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    status = Column(String(30), nullable=False)
    score = Column(Numeric(5, 2), nullable=False)
    result_summary = Column(Text, nullable=False)
    evaluated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    findings = relationship("Finding", back_populates="control_result", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=uuid_str)
    control_result_id = Column(String, ForeignKey("control_results.id"), nullable=False)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(30), nullable=False, default="high")
    status = Column(String(30), nullable=False, default="open")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    control_result = relationship("ControlResult", back_populates="findings")


class Risk(Base):
    __tablename__ = "risks"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(120), nullable=True)
    likelihood = Column(Integer, nullable=False, default=3)   # 1-5
    impact = Column(Integer, nullable=False, default=3)       # 1-5
    owner = Column(String(255), nullable=True)
    status = Column(String(30), nullable=False, default="open")  # open | mitigating | accepted | closed
    treatment = Column(String(30), nullable=False, default="mitigate")  # mitigate | accept | transfer | avoid
    linked_control_code = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    @property
    def score(self) -> int:
        return (self.likelihood or 0) * (self.impact or 0)

    @property
    def rating(self) -> str:
        s = self.score
        if s >= 15:
            return "critical"
        if s >= 9:
            return "high"
        if s >= 4:
            return "medium"
        return "low"


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(120), nullable=True)
    version = Column(String(30), nullable=False, default="1.0")
    status = Column(String(30), nullable=False, default="draft")  # draft | in_review | approved | retired
    owner = Column(String(255), nullable=True)
    body = Column(Text, nullable=True)
    linked_framework = Column(String(255), nullable=True)
    review_date = Column(String(30), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(120), nullable=True)
    file_name = Column(String(255), nullable=True)
    file_path = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(30), nullable=False, default="info")  # info | warning | critical
    is_read = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WorkflowTask(Base):
    __tablename__ = "workflow_tasks"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    title = Column(String(255), nullable=False)
    related_type = Column(String(50), nullable=True)  # finding | risk | policy | control
    related_id = Column(String, nullable=True)
    assignee = Column(String(255), nullable=True)
    stage = Column(String(30), nullable=False, default="backlog")  # backlog | in_progress | review | done
    due_date = Column(String(30), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    service_provided = Column(String(255), nullable=True)
    risk_tier = Column(String(30), nullable=False, default="medium")  # low | medium | high | critical
    contact_email = Column(String(255), nullable=True)
    last_reviewed = Column(String(30), nullable=True)
    status = Column(String(30), nullable=False, default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLogEntry(Base):
    __tablename__ = "audit_log_entries"
    id = Column(String, primary_key=True, default=uuid_str)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    actor_email = Column(String(255), nullable=True)
    action = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
