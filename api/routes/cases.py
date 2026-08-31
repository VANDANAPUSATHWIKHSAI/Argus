from fastapi import APIRouter
router = APIRouter()

@router.get('/{case_id}')
async def get_case(case_id: str):
    pass
