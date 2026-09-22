# Argus FastAPI entry point
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import evidence, cases, reports, query, auth

app = FastAPI(title='Argus', description='Multi-Agent Digital Forensic Investigation Platform')

import os

_allowed_origins_env = os.environ.get("ARGUS_ALLOWED_ORIGINS", "")
if _allowed_origins_env:
    _allowed_origins = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    # Development fallback — restrict in production by setting ARGUS_ALLOWED_ORIGINS
    _allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "ok", "service": "ARGUS Digital Forensics API", "version": "1.0.0"}
app.include_router(evidence.router, prefix='/evidence', tags=['Evidence'])
app.include_router(cases.router, prefix='/cases', tags=['Cases'])
app.include_router(reports.router, prefix='/reports', tags=['Reports'])
app.include_router(query.router, prefix='/cases', tags=['Query'])
app.include_router(auth.router, prefix='/auth', tags=['Authentication'])


