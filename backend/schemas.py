from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Literal

class LogCreate(BaseModel):
    source_ip: str
    event_type: str
    severity: str
    raw_message: str
    tenant_id: Optional[str] = "default"
    # NEW (all optional, so old clients and old scripts keep working):
    timestamp: Optional[datetime] = None            # when the event really happened
    username: Optional[str] = Field(default=None, max_length=128)
    host: Optional[str] = Field(default=None, max_length=128)
    outcome: Optional[Literal["success", "failure"]] = None

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    event_type: str
    severity: str
    raw_message: str
    tenant_id: str
    username: Optional[str] = None
    host: Optional[str] = None
    outcome: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    is_active: bool

    class Config:
        from_attributes = True
