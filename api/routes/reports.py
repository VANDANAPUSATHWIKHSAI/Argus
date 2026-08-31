from fastapi import APIRouter
router = APIRouter()

@router.get('/{case_id}/report')
async def get_report(case_id: str):
    pass
