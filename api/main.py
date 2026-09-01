# Argus FastAPI entry point
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import evidence, cases, reports, query

app = FastAPI(title='Argus', description='Multi-Agent Digital Forensic Investigation Platform')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

