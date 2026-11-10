from fastapi import APIRouter, Depends

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


@router.post("/users")
async def create_user(payload: dict):
    return payload
