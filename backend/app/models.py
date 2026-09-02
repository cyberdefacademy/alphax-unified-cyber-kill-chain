import uuid
from datetime import datetime, timezone
from enum import IntEnum
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey, Boolean, JSON, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def utcnow():
    return datetime.now(timezone.utc)

class UckcPhaseEnum(IntEnum):
    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    SOCIAL_ENGINEERING = 4
    EXPLOITATION = 5
    PERSISTENCE = 6
    DEFENSE_EVASION = 7
    COMMAND_AND_CONTROL = 8
    PIVOTING = 9
    DISCOVERY = 10
    PRIVILEGE_ESCALATION = 11
    EXECUTION = 12
    CREDENTIAL_ACCESS = 13
    LATERAL_MOVEMENT = 14
    COLLECTION = 15
    EXFILTRATION = 16
    IMPACT = 17
    OBJECTIVES = 18

class EngagementStatusStr(str):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    BLOCKED_NEEDS_INPUT = "blocked_needs_input"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class CommandStatus(str):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"

# --- Tables ---

class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    scope_cidr: Mapped[str] = mapped_column(String(512), nullable=False, default="192.168.56.0/24")
    status: Mapped[str] = mapped_column(String(32), default=EngagementStatusStr.DRAFT)
    current_phase: Mapped[int] = mapped_column(Integer, default=UckcPhaseEnum.RECONNAISSANCE)
    authorized_by: Mapped[str] = mapped_column(String(128), default="operator")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    targets: Mapped[list["Target"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    commands: Mapped[list["Command"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    credentials: Mapped[list["Credential"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    os_fingerprint: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ports: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # [{port, protocol, service, version, state}]
    services: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="discovered")
    discovered_in_phase: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="targets")

class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    password_or_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    hash_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_phase: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cracked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="credentials")

class Command(Base):
    __tablename__ = "commands"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"))
    phase: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_command: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=CommandStatus.PENDING_APPROVAL)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped["Engagement"] = relationship(back_populates="commands")
    result: Mapped["Result | None"] = relationship(back_populates="command", cascade="all, delete-orphan", uselist=False)

class Result(Base):
    __tablename__ = "results"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    command_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("commands.id", ondelete="CASCADE"), unique=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    command: Mapped["Command"] = relationship(back_populates="result")

class AssetEdge(Base):
    __tablename__ = "asset_edges"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"))
    source_target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"))
    dest_target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"))
    edge_type: Mapped[str] = mapped_column(String(64))  # pivot, lateral_movement, c2, etc
    phase: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

# Helper for WS knowledge graph
class KnowledgeGraphEdgeType(str):
    PIVOT = "pivot"
    LATERAL_MOVEMENT = "lateral_movement"
    C2 = "c2"
    DISCOVERY = "discovery"
