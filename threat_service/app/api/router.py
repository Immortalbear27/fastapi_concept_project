from fastapi import APIRouter, Depends, status
from app.models.schemas import ThreatRequest, ThreatResponse
from app.dependencies.auth import get_current_user
from app.analysis.threat_analysis import analyse_threat, cpu_intensive_fingerprint
from app.utils.decorators import timed
from concurrent.futures import ThreadPoolExecutor
import asyncio

# Overarching process:
# FastAPI conducts these processes when a HTTP request hits /threat/analyze:
# - Read request body
# - Parse JSON
# - Validate against ThreatRequest
# - Reject the request if invalid
# - Resolve dependencies
# - Only after all this does it call analyze_threat(...)

# Create thread pool for offloading CPU-bound work from the event loop:
executor = ThreadPoolExecutor(max_workers = 4)

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

# Decorator that measures the time of execution:
@timed("threat_analyze")

async def analyse_threat_endpoint(
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
    user = Depends(get_current_user),
):
    """
    
    Args:
        request (ThreatRequest): The user request to the server.
        current_user: Defaults to Depends(get_current_user).
    """
    
    # Simulating ASync processes:
    await asyncio.sleep(0.2)
    
    # Adding CPU-intensive fingerprint, for testing purposes:
    loop = asyncio.get_running_loop()
    fingerprint = await loop.run_in_executor(
        executor,
        cpu_intensive_fingerprint,
        request.payload_data,
    )
    
    # Just for testing purposes:
    response = analyse_threat(request.payload_data)
    response.indicators.append(f"fingerprint:{fingerprint[:12]}")
    return response
    
    # # Analyses payload and then returns the associated threat assessment structure:
    # return analyse_threat(request.payload_data)