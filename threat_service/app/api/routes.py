from fastapi import APIRouter, Depends

from app.models.schemas import ThreatRequest, ThreatResponse
from app.dependencies.auth import get_current_user

router = APIRouter(prefix = "/api")

@router.post("/analyse", response_model = ThreatResponse)
async def analyse_threat(
    request: ThreatRequest,
    current_user = Depends(get_current_user),
):
    """
    TODO:
    - Accept a validated request body
    - Simulate async threat analysis
    - Return a structured response
    
    Args:
        request (ThreatRequest): _description_
        current_user (_type_, optional): _description_. Defaults to Depends(get_current_user).
    """
    pass