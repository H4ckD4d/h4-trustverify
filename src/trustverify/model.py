from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Integer, UniqueConstraint
from .db import Base, uid
from datetime import datetime

class ApprovalRequest(Base):
    __tablename__='approval_requests'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    creator: Mapped[str]=mapped_column(String(100))
    reference: Mapped[str]=mapped_column(String(80))
    payload_sha256: Mapped[str]=mapped_column(String(64))
    required: Mapped[int]=mapped_column(Integer,default=2)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True))
    status: Mapped[str]=mapped_column(String(20),default='pending')

class Approval(Base):
    __tablename__='approvals'
    __table_args__=(UniqueConstraint('request_id','actor_id',name='unique_approver'),)
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    request_id: Mapped[str]=mapped_column(String(36),index=True)
    actor_id: Mapped[str]=mapped_column(String(100))
