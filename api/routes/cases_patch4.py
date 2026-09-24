import re

def update_close_case(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    old_close = """@router.put("/{case_id}/close")
async def close_case_endpoint(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    \"\"\"
    Close an active case globally.
    \"\"\"
    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)
    success = close_case(tenant_id=x_tenant_id, case_id=clean_case_id)"""

    new_close = """@router.put("/{case_id}/close")
async def close_case_endpoint(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    \"\"\"
    Close an active case globally.
    \"\"\"
    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)
    
    # Custom db update to add closed_by
    from config.settings import settings
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password, connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute(
            "UPDATE cases SET status = 'closed', closed_at = NOW(), closed_by = %s WHERE case_id = %s AND tenant_id = %s;",
            (current_user["id"], clean_case_id, x_tenant_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Error closing case directly: {e}")
        
    success = close_case(tenant_id=x_tenant_id, case_id=clean_case_id)"""

    new_content = content.replace(old_close, new_close)
    
    # Also update get_recent_activity to select closed_by
    old_activity = """cur.execute("SELECT case_id, created_by, created_at, closed_at FROM cases WHERE tenant_id = %s", (x_tenant_id,))"""
    new_activity = """cur.execute("SELECT case_id, created_by, created_at, closed_at, closed_by FROM cases WHERE tenant_id = %s", (x_tenant_id,))"""
    new_content = new_content.replace(old_activity, new_activity)
    
    old_activity_parse = """case_id, c_by, created_at, closed_at = row"""
    new_activity_parse = """case_id, c_by, created_at, closed_at, closed_by = row"""
    new_content = new_content.replace(old_activity_parse, new_activity_parse)
    
    old_closed_append = """            if closed_at:
                activity.append({
                    "action": "Closed Case",
                    "case_id": case_id,
                    "created_by": mapped_name,
                    "created_at": closed_at.isoformat() if hasattr(closed_at, "isoformat") else str(closed_at),
                    "details": f"Case {case_id} was closed"
                })"""
                
    new_closed_append = """            if closed_at:
                c_by_name = user_map.get(closed_by, closed_by) if closed_by else "Admin User"
                activity.append({
                    "action": "Closed Case",
                    "case_id": case_id,
                    "created_by": c_by_name,
                    "created_at": closed_at.isoformat() if hasattr(closed_at, "isoformat") else str(closed_at),
                    "details": f"Case {case_id} was closed"
                })"""
    new_content = new_content.replace(old_closed_append, new_closed_append)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

update_close_case("api/routes/cases.py")
