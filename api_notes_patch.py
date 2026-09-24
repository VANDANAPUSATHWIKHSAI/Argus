import re

cases_path = "api/routes/cases.py"
with open(cases_path, "r", encoding="utf-8") as f:
    cases_code = f.read()

# 1. Update get_recent_activity to include case_notes
activity_patch = """
        # 4. Case Notes
        cur.execute(
            \"\"\"
            SELECT note_id, case_id, created_by, created_at, title, type
            FROM case_notes
            WHERE tenant_id = %s
            \"\"\",
            (x_tenant_id,)
        )
        for row in cur.fetchall():
            note_id, case_id, created_by, created_at, title, note_type = row
            activity.append({
                "action": "Created Note",
                "case_id": case_id,
                "created_by": user_map.get(created_by, created_by),
                "created_by_id": created_by,
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                "details": f"{title} ({note_type})"
            })
"""
# Insert before "conn.close()"
cases_code = cases_code.replace("conn.close()", activity_patch + "\n        conn.close()", 1)


# 2. Add new endpoints
new_endpoints = """
class CaseNoteModel(BaseModel):
    title: str
    content: str
    type: str
    priority: str
    related_evidence_id: Optional[str] = None
    related_finding_id: Optional[str] = None

@router.get("/{case_id}/notes")
async def get_case_notes(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    from config.settings import settings
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        cur.execute(
            \"\"\"
            SELECT note_id, title, content, type, priority, created_by, created_at, updated_at, related_evidence_id, related_finding_id
            FROM case_notes
            WHERE case_id = %s AND tenant_id = %s
            ORDER BY updated_at DESC
            \"\"\",
            (case_id, x_tenant_id)
        )
        notes = []
        for row in cur.fetchall():
            notes.append({
                "noteId": row[0],
                "caseId": case_id,
                "title": row[1],
                "content": row[2],
                "type": row[3],
                "priority": row[4],
                "createdBy": row[5],
                "createdAt": row[6].isoformat() if hasattr(row[6], "isoformat") else str(row[6]),
                "updatedAt": row[7].isoformat() if hasattr(row[7], "isoformat") else str(row[7]),
                "relatedEvidenceId": row[8],
                "relatedFindingId": row[9]
            })
        conn.close()
        return {"status": "SUCCESS", "data": notes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{case_id}/notes")
async def create_case_note(
    case_id: str,
    note: CaseNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    from config.settings import settings
    import psycopg2
    import uuid
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        note_id = f"NOTE-{str(uuid.uuid4())[:8].upper()}"
        cur.execute(
            \"\"\"
            INSERT INTO case_notes (note_id, case_id, tenant_id, title, content, type, priority, created_by, related_evidence_id, related_finding_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            \"\"\",
            (note_id, case_id, x_tenant_id, note.title, note.content, note.type, note.priority, current_user.get("name", "Analyst"), note.related_evidence_id, note.related_finding_id)
        )
        conn.commit()
        conn.close()
        return {"status": "SUCCESS", "noteId": note_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{case_id}/notes/{note_id}")
async def update_case_note(
    case_id: str,
    note_id: str,
    note: CaseNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    from config.settings import settings
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        cur.execute(
            \"\"\"
            UPDATE case_notes 
            SET title = %s, content = %s, type = %s, priority = %s, updated_at = now(), related_evidence_id = %s, related_finding_id = %s
            WHERE note_id = %s AND case_id = %s AND tenant_id = %s
            \"\"\",
            (note.title, note.content, note.type, note.priority, note.related_evidence_id, note.related_finding_id, note_id, case_id, x_tenant_id)
        )
        conn.commit()
        conn.close()
        return {"status": "SUCCESS"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{case_id}/notes/{note_id}")
async def delete_case_note(
    case_id: str,
    note_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    from config.settings import settings
    import psycopg2
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        cur.execute("DELETE FROM case_notes WHERE note_id = %s AND case_id = %s AND tenant_id = %s", (note_id, case_id, x_tenant_id))
        conn.commit()
        conn.close()
        return {"status": "SUCCESS"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
"""

cases_code += "\n\n" + new_endpoints

with open(cases_path, "w", encoding="utf-8") as f:
    f.write(cases_code)

print("Patch applied to cases.py")
