"""Bounded MVP API. Never deploy this demo unchanged with real customer data."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta, date
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Base, AuditEvent, audit, engine_for_env, uid
from .security import current_actor, require_write
from .model import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = engine_for_env()
    app.state.engine = engine
    if os.getenv('H4_AUTO_CREATE_TABLES') == '1':
        Base.metadata.create_all(engine)
    try:
        yield
    finally:
        engine.dispose()

def session_dep(request: Request):
    with Session(request.app.state.engine) as session:
        yield session

def require_tenant(session: Session, model, entity_id: str, tenant_id: str):
    item = session.scalar(select(model).where(model.id == entity_id, model.tenant_id == tenant_id))
    if item is None:
        raise HTTPException(404, 'Not found')
    return item

app = FastAPI(title='H4 TrustVerify', version='0.1.0', lifespan=lifespan,
              description='Tenant-scoped technical MVP; not production-ready.')

@app.middleware('http')
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

@app.get('/healthz', include_in_schema=False)
def healthz():
    return {'ok': True}

@app.get('/v1/audit')
def audit_list(limit:int=Query(default=50,ge=1,le=100),offset:int=Query(default=0,ge=0,le=10000),
               auth=Depends(current_actor),session: Session=Depends(session_dep)):
    rows = session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == auth['tenant_id'])
                           .order_by(AuditEvent.created_at.desc(),AuditEvent.id.desc())
                           .offset(offset).limit(limit)).all()
    return {'events': [{'kind':r.kind,'resource_id':r.resource_id,'actor_id':r.actor_id,
                        'at':r.created_at.isoformat()} for r in rows],
            'limit':limit,'offset':offset}

import re
from sqlalchemy.exc import IntegrityError

class NewRequest(BaseModel):
    reference: str=Field(min_length=3,max_length=80)
    payload_sha256: str=Field(pattern='^[0-9a-f]{64}$')
    required: int=Field(default=2,ge=2,le=5)
    expires_minutes: int=Field(default=60,ge=1,le=10080)

@app.post('/v1/requests',status_code=201)
def create_request(payload: NewRequest,auth=Depends(require_write),session: Session=Depends(session_dep)):
    request=ApprovalRequest(tenant_id=auth['tenant_id'],creator=auth['actor_id'],
        reference=payload.reference,payload_sha256=payload.payload_sha256,
        required=payload.required,expires_at=datetime.now(timezone.utc)+timedelta(minutes=payload.expires_minutes),status='pending')
    session.add(request);session.flush();audit(session,auth,'request.created',request.id);session.commit()
    return {'id':request.id,'reference':request.reference,'required':request.required,'status':request.status}

@app.get('/v1/requests/{request_id}')
def get_request(request_id: str,auth=Depends(current_actor),session: Session=Depends(session_dep)):
    request=require_tenant(session,ApprovalRequest,request_id,auth['tenant_id'])
    count=session.scalar(select(func.count()).select_from(Approval).where(Approval.tenant_id==auth['tenant_id'],Approval.request_id==request_id))
    status='expired' if datetime.now(timezone.utc)>request.expires_at.replace(tzinfo=timezone.utc) and request.status=='pending' else request.status
    return {'id':request.id,'reference':request.reference,'status':status,'approvals':count,'required':request.required}

@app.post('/v1/requests/{request_id}/approve')
def approve(request_id: str,auth=Depends(require_write),session: Session=Depends(session_dep)):
    request=require_tenant(session,ApprovalRequest,request_id,auth['tenant_id'])
    if request.status!='pending':
        raise HTTPException(409,'Request not pending')
    if datetime.now(timezone.utc)>request.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(409,'Request expired')
    if auth['actor_id']==request.creator:
        raise HTTPException(403,'Requester cannot self-approve')
    existing=session.scalar(select(Approval).where(Approval.request_id==request_id,Approval.tenant_id==auth['tenant_id'],Approval.actor_id==auth['actor_id']))
    if existing:
        raise HTTPException(409,'Actor already approved')
    session.add(Approval(tenant_id=auth['tenant_id'],request_id=request_id,actor_id=auth['actor_id']))
    session.flush()
    count=session.scalar(select(func.count()).select_from(Approval).where(Approval.tenant_id==auth['tenant_id'],Approval.request_id==request_id))
    if count>=request.required:
        request.status='approved'
    audit(session,auth,'request.approved',request_id);session.commit()
    return {'id':request_id,'status':request.status,'approvals':count,'required':request.required}

@app.post('/v1/requests/{request_id}/cancel')
def cancel_request(request_id: str,auth=Depends(require_write),session: Session=Depends(session_dep)):
    request=require_tenant(session,ApprovalRequest,request_id,auth['tenant_id'])
    if request.status!='pending':
        raise HTTPException(409,'Only pending requests can be canceled')
    if auth['actor_id']!=request.creator and auth['role']!='admin':
        raise HTTPException(403,'Only creator or admin can cancel')
    request.status='canceled'
    audit(session,auth,'request.canceled',request.id);session.commit()
    return {'id':request.id,'status':request.status}
