import re

def update_activity(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    new_activity_fn = """@router.get("/activity", response_model=Dict[str, Any])
async def get_recent_activity(
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    activity = []
    
    user_map = {"Admin": "Admin User", "analyst_api": "Analyst", "Analyst_api": "Analyst"}
    try:
        from config.settings import settings
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM users")
        for row in cur.fetchall():
            user_map[str(row[0])] = row[1]
            
        # 1. Case Creation
        cur.execute("SELECT case_id, created_by, created_at, closed_at FROM cases WHERE tenant_id = %s", (x_tenant_id,))
        for row in cur.fetchall():
            case_id, c_by, created_at, closed_at = row
            mapped_name = user_map.get(c_by, c_by)
            activity.append({
                "action": "Created Case",
                "case_id": case_id,
                "created_by": mapped_name,
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                "details": case_id
            })
            if closed_at:
                activity.append({
                    "action": "Closed Case",
                    "case_id": case_id,
                    "created_by": mapped_name,
                    "created_at": closed_at.isoformat() if hasattr(closed_at, "isoformat") else str(closed_at),
                    "details": f"Case {case_id} was closed"
                })

        # 2. Uploaded Evidence
        cur.execute(
            \"\"\"
            SELECT e.evidence_id, e.case_id, e.filename, e.uploaded_by, e.upload_timestamp
            FROM evidence e
            INNER JOIN cases c ON e.case_id = c.case_id
            WHERE c.tenant_id = %s
            \"\"\", 
            (x_tenant_id,)
        )
        for row in cur.fetchall():
            u_by = row[3] if row[3] else ""
            activity.append({
                "action": "Uploaded Evidence",
                "case_id": row[1],
                "created_by": user_map.get(u_by, u_by),
                "created_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
                "details": row[2]
            })

        # 3. Analyst Findings
        cur.execute(
            \"\"\"
            SELECT f.case_id, f.created_at, f.fact, f.source_engine, f.reviewed_by, f.review_status, f.timestamp
            FROM fir_findings f
            INNER JOIN cases c ON f.case_id = c.case_id
            WHERE c.tenant_id = %s
            ORDER BY f.timestamp DESC
            \"\"\",
            (x_tenant_id,)
        )
        
        # Deduplicate findings by action, case, user, and approximate minute
        finding_events = {}
        for row in cur.fetchall():
            case_id, created_at, fact, source_engine, reviewed_by, review_status, review_time = row
            
            action_name = None
            evt_time = None
            if review_status in ('analyst_confirmed', 'analyst_rejected') and review_time:
                action_name = "Confirmed Finding" if review_status == 'analyst_confirmed' else "Rejected Finding"
                evt_time = review_time
            elif source_engine == 'manual' or review_status == 'manual_entry':
                action_name = "Created Finding"
                evt_time = created_at
                
            if action_name and evt_time:
                # Group by minute
                minute_key = evt_time.replace(second=0, microsecond=0)
                user_name = user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst"
                group_key = (action_name, case_id, user_name, minute_key)
                
                if group_key not in finding_events:
                    finding_events[group_key] = {
                        "action": action_name,
                        "case_id": case_id,
                        "created_by": user_name,
                        "created_at": evt_time,
                        "details": fact[:50] + "..." if fact and len(fact) > 50 else fact,
                        "count": 1
                    }
                else:
                    finding_events[group_key]["count"] += 1

        for grp, evt in finding_events.items():
            if evt["count"] > 1:
                evt["action"] = f"{evt['action']} ({evt['count']})"
                evt["details"] = f"Multiple findings ({evt['count']}) updated"
            evt["created_at"] = evt["created_at"].isoformat() if hasattr(evt["created_at"], "isoformat") else str(evt["created_at"])
            activity.append(evt)
            
        conn.close()
    except Exception as e:
        print(f"[DB WARNING] Could not fetch comprehensive activity: {e}")
        
    activity.sort(key=lambda x: x["created_at"], reverse=True)
    
    return {
        "status": "SUCCESS",
        "data": activity[:20]
    }"""

    # Use regex to find and replace the whole function
    pattern = re.compile(r'@router\.get\("/activity", response_model=Dict\[str, Any\]\)\nasync def get_recent_activity\([\s\S]*?return \{\n\s*"status": "SUCCESS",\n\s*"data": activity\[:20\]\n\s*\}', re.MULTILINE)
    
    new_content = pattern.sub(new_activity_fn, content)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

update_activity("api/routes/cases.py")
