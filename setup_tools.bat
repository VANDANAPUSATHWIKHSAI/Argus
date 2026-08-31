@echo off
rem ══════════════════════════════════════════════════════════════════════════════
rem Argus — Windows Deployment Setup & Health Check
rem ══════════════════════════════════════════════════════════════════════════════
rem This batch script automates the installation of Python dependencies and
rem checks the status of database connections and external tools on Windows.
rem ══════════════════════════════════════════════════════════════════════════════

echo ======================================================================
echo               Argus — Windows Setup & Health Check
echo ======================================================================

rem ──────────────────────────────────────────────────────────────────────────────
rem Phase 1: Python Dependencies
rem ──────────────────────────────────────────────────────────────────────────────
echo.
echo [Phase 1/4] Installing Python dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install Python dependencies. Please check python/pip path.
    pause
    exit /b 1
)
echo [OK] Python dependencies installed successfully.

rem ──────────────────────────────────────────────────────────────────────────────
rem Phase 2: Database Connectivity Checks
rem ──────────────────────────────────────────────────────────────────────────────
echo.
echo [Phase 2/4] Verifying PostgreSQL and MinIO connectivity...
set PYTHONPATH=.
python -c "
import sys
try:
    from config.settings import settings
except ImportError as e:
    print('Failed to import config.settings. Ensure you are running this from the argus directory.', file=sys.stderr)
    sys.exit(1)

# Check PostgreSQL
try:
    import psycopg2
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=5
    )
    conn.close()
    print('  OK - PostgreSQL database is reachable!')
except Exception as e:
    print(f'  FAIL - PostgreSQL is unreachable!', file=sys.stderr)
    print(f'  Detail: {e}', file=sys.stderr)
    sys.exit(1)

# Check MinIO
try:
    from minio import Minio
    endpoint = settings.minio_endpoint
    if '://' in endpoint:
        endpoint = endpoint.split('://')[1]
    client = Minio(
        endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure
    )
    client.list_buckets()
    print('  OK - MinIO storage is reachable!')
except Exception as e:
    print(f'  FAIL - MinIO is unreachable!', file=sys.stderr)
    print(f'  Detail: {e}', file=sys.stderr)
    sys.exit(1)
"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Database connectivity checks failed. Please start Docker containers.
    pause
    exit /b 1
)
echo [OK] Database connectivity checks passed successfully!

rem ──────────────────────────────────────────────────────────────────────────────
rem ──────────────────────────────────────────────────────────────────────────────
rem Phase 3: External Forensic Tools & Dependencies Discovery
rem ──────────────────────────────────────────────────────────────────────────────
echo.
echo [Phase 3/4] Running ARGUS external forensic tools & dependencies discovery check...
python "%~dp0tools\check_external_forensics_tools.py"
if %ERRORLEVEL% neq 0 (
    echo.
    echo [WARNING] Some external forensic tools or rules are missing.
    echo Please refer to the 'DOWNLOAD EXTERNALLY' section above to complete installation.
)

rem ──────────────────────────────────────────────────────────────────────────────
rem Phase 4: Summary Status Report
rem ──────────────────────────────────────────────────────────────────────────────
echo.
echo Deployment & discovery checks completed.
pause
