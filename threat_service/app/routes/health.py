from fastapi import APIRouter, Depends
from app.dependencies.auth import get_current_user

router = APIRouter(
    prefix = "/health",
    tags = ["Health"]
)

@router.get("/", dependencies = [Depends(get_current_user)])
def health_check():
    return {
        "status": "ok",
        "service": "example-api"
    }