import re

def update_activity(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # The block we want to replace
    old_findings_block = """            # If created manually by analyst
            if source_engine == 'manual':
                activity.append({
                    "action": "Created Finding",
                    "case_id": case_id,
                    "created_by": user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst",
                    "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                    "details": fact[:50] + "..." if fact and len(fact) > 50 else fact
                })
            # If reviewed by analyst
            if review_status in ('verified', 'rejected') and review_time:
                activity.append({
                    "action": f"{review_status.capitalize()} Finding",
                    "case_id": case_id,
                    "created_by": user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst",
                    "created_at": review_time.isoformat() if hasattr(review_time, "isoformat") else str(review_time),
                    "details": fact[:50] + "..." if fact and len(fact) > 50 else fact
                })"""

    new_findings_block = """            # Analyst confirmed or rejected
            if review_status in ('analyst_confirmed', 'analyst_rejected') and review_time:
                action_name = "Confirmed Finding" if review_status == 'analyst_confirmed' else "Rejected Finding"
                activity.append({
                    "action": action_name,
                    "case_id": case_id,
                    "created_by": user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst",
                    "created_at": review_time.isoformat() if hasattr(review_time, "isoformat") else str(review_time),
                    "details": fact[:50] + "..." if fact and len(fact) > 50 else fact
                })
            elif source_engine == 'manual' or review_status == 'manual_entry':
                activity.append({
                    "action": "Created Finding",
                    "case_id": case_id,
                    "created_by": user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst",
                    "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                    "details": fact[:50] + "..." if fact and len(fact) > 50 else fact
                })"""

    new_content = content.replace(old_findings_block, new_findings_block)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

update_activity("api/routes/cases.py")
