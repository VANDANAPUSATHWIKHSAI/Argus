# Argus FastAPI entry point
from fastapi import FastAPI
from api.routes import evidence, cases, reports, query

app = FastAPI(title='Argus', description='Multi-Agent Digital Forensic Investigation Platform')
app.include_router(evidence.router, prefix='/evidence', tags=['Evidence'])
app.include_router(cases.router, prefix='/cases', tags=['Cases'])
app.include_router(reports.router, prefix='/reports', tags=['Reports'])
app.include_router(query.router, prefix='/cases', tags=['Query'])

