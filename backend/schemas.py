from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class LogCreate(BaseModel):
    source_ip: str
    event_type: str
    severity: str
    raw_message: str
    tenant_id: Optional[str] = "default"

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    event_type: str
    severity: str
    raw_message: str
    tenant_id: str

    class Config:
        from_attributes = True
