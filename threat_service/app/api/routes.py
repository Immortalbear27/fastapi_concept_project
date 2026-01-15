from fastapi import APIRouter, Depends, status
from app.models.schemas import ThreatRequest, ThreatResponse
from app.dependencies.auth import get_current_user

# Overarching process:
# FastAPI conducts these processes when a HTTP request hits /threat/analyze:
# - Read request body
# - Parse JSON
# - Validate against ThreatRequest
# - Reject the request if invalid
# - Resolve dependencies
# - Only after all this does it call analyze_threat(...)

# Allows for modular APIs, keeps routes separate from application bootstrapping,
# and enables reuse and scaling.
router = APIRouter(
    # Groups related endpoints together, and is future-proofing for 
    # /threat/analyze and /threat/history, etc...
    prefix = "/threat",
    tags = ["Threat Analysis"]
    )

# NOTE for above: router = APIRouter(prefix="/threat") effectively translates to:
# 'Everything in this file belongs under /threat/*'

# Declares HTTP method, path, response schema and status code:
# NOTE: This is also the use of a decorator in action.
@router.post(
    "/analyze", 
    # This line enforces correct output, 
    # prevents accidental data leakage and acts as a response firewall.
    response_model = ThreatResponse, 
    status_code = status.HTTP_200_OK
    )

# NOTE for above: @router.post("/analyze") effectively translates to:
# 'Register the function below as the handler for POST /threat/analyze'
# Also, the line above combined with the parameter 'response_model = ThreatResponse'
# also has these key properties:
# - Records the function reference, attaches metadata such as HTTP method, path,
# input and output model, and status code

# 
async def analyse_threat(
    # The below line does this:
    # - Parses JSON
    # - Validates it against the schema
    # - Rejects invalid data automatically
    # - Injects a trusted object into your function
    request: ThreatRequest,
    # The line below effectively translates to this:
    # - 'Before calling this function, FastAPI must run 'get_current_user', and inject its result'
    # If this call raises an exception, then the function is never called, 
    # and FastAPI returns a HTTP error automatically
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
    
    # Placeholder response:
    return ThreatResponse(
        risk_score = 0.0,
        classification_label = "benign",
        indicators = []
    )