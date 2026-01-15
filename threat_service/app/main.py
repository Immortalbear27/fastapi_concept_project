from fastapi import FastAPI
from app.api.routes import router as threat_router

# TODO:
# - Instantiate the FastAPI application
# Include the API router
# Add a simple startup event (print/log something)

app = FastAPI(
    title = "Threat Analysis Service",
    version = "0.1.0",
    description = "API for analysing network traffic and returning threat assessments"
)

# What this actually does:
# 'Take all the routes registered inside threat_router and attach them to this application'
# The router contains a prefix of /threat as well as router.post("/analyze"), the final
# resolved endpoint becomes: POST /threat/analyze
app.include_router(threat_router)

@app.on_event("startup")
async def startup_event():
    print("Threat Analysis Service started")
    # TODO: Simulate startup work
    pass