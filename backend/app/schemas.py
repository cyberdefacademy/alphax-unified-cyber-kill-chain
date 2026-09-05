from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
import uuid

class EngagementCreate(BaseModel):
    name: str = Field(..., max_length=256, examples=["VulnHub Kioptrix - Week 12"])
    scope_cidr: str = Field(default="192.168.56.0/24", examples=["192.168.56.0/24"])
    authorized_by: str = Field(default="operator")

class EngagementOut(BaseModel):
    id: uuid.UUID
    name: str
    scope_cidr: str
    status: str
    current_phase: int
    authorized_by: str
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class EngagementUpdate(BaseModel):
    name: Optional[str] = None
    scope_cidr: Optional[str] = None
    status: Optional[str] = None
    current_phase: Optional[int] = None

class TargetCreate(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os_fingerprint: Optional[str] = None
    ports: Optional[Any] = None
    discovered_in_phase: Optional[int] = None

class TargetOut(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    ip: str
    hostname: Optional[str]
    os_fingerprint: Optional[str]
    ports: Optional[Any]
    status: str
    discovered_in_phase: Optional[int]
    created_at: datetime
    class Config:
        from_attributes = True

class CredentialCreate(BaseModel):
    target_id: Optional[uuid.UUID] = None
    username: str
    password_or_hash: Optional[str] = None
    hash_type: Optional[str] = None
    source_phase: Optional[int] = None
    cracked: bool = False

class CredentialOut(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: Optional[uuid.UUID]
    username: str
    password_or_hash: Optional[str]
    hash_type: Optional[str]
    source_phase: Optional[int]
    cracked: bool
    created_at: datetime
    class Config:
        from_attributes = True

class CommandCreate(BaseModel):
    phase: int = Field(..., ge=1, le=18)
    tool_name: str
    params: Optional[dict] = None
    raw_command: Optional[str] = None  # if None, assembled from tool + params

class CommandOut(BaseModel):
    id: uuid.UUID
    engagement_id: uuid.UUID
    phase: int
    tool_name: str
    raw_command: str
    params: Optional[dict]
    status: str
    approved_by: Optional[str]
    stdout: Optional[str]
    stderr: Optional[str]
    exit_code: Optional[int]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    class Config:
        from_attributes = True

class ResultOut(BaseModel):
    id: uuid.UUID
    command_id: uuid.UUID
    raw_output: Optional[str]
    parsed_data: Optional[dict]
    created_at: datetime
    class Config:
        from_attributes = True

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ToolSpecOut(BaseModel):
    name: str
    template: str
    description: str
    params_schema: dict
