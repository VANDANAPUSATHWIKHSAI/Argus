import os
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

# Argus FastAPI entry point
from contextlib import asynccontextmanager
import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import evidence, cases, reports, query, auth
from databases.postgres_pool import PostgresConnectionPool

def _prewarm_heavy_modules():
    """Pre-warm heavy grammar compilers (e.g. ioc_finder) in background to eliminate first-request latency."""
    try:
        import ioc_finder
        _ = ioc_finder.find_iocs("127.0.0.1")
    except Exception:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize bounded thread-safe PostgreSQL connection pool
    PostgresConnectionPool.initialize(minconn=2, maxconn=20)
    # Asynchronously pre-warm grammars without blocking startup
    threading.Thread(target=_prewarm_heavy_modules, daemon=True).start()
    # Startup recovery sweep for interrupted background evidence jobs
    try:
        from api.routes.evidence import recover_interrupted_evidence_jobs
        recovered = recover_interrupted_evidence_jobs()
        if recovered > 0:
            print(f"  [RECOVERY] Safely re-dispatched {recovered} interrupted evidence jobs from PostgreSQL ism_state.")
    except Exception as rec_err:
        print(f"  [RECOVERY NOTICE] Startup recovery check: {rec_err}")
    yield
    # Cleanup pool on shutdown
    PostgresConnectionPool.close_all()

app = FastAPI(
    title='Argus',
    description='Multi-Agent Digital Forensic Investigation Platform',
    lifespan=lifespan
)

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


