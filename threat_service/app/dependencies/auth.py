from fastapi import Header, HTTPException, status

# In a real system, the key comes from the config or environment variables:
API_KEY = "secret_api_key"

# This functions isn't directly called, but is instead ran as a dependency in routes.py
# This call is used to run the function, in order to check authentication before running any
# real processing logic/code.
async def get_current_user(
    # The Header part tells FastAPI to 'extract the value of the API-KEY HTTP Header'
    # FastAPI will automatically read headers, validate presence and inject the value into the function.
    x_api_key: str = Header(...)
):
    """
    TODO:
    - Validate that an Authorization header exists
    - Reject missing/invalid headers
    - Return a user context (dict is fine)

    Args:
        authorization (str | None, optional): _description_. Defaults to Header(default = None).
    """
    if x_api_key != API_KEY:
        # Controlled HTTP response if authentication key is wrong/mis-matched:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Ivalid or missing API key",
        )
        # Returning details proves authentication succeeded, allows downstream logic 
        # to use identity info later, and mirrors real-world patterns
    return {
        "api_key": x_api_key
    }