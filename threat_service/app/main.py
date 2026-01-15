from fastapi import FastAPI

# TODO:
# - Instantiate the FastAPI application
# Include the API router
# Add a simple startup event (print/log something)

app = FastAPI(
    title = "Threat Analysis Service",
    version = "0.1.0",
)

# TODO: Include router here

@app.on_event("startup")
async def startup_event():
    # TODO: Simulate startup work
    pass