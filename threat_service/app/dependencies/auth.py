from fastapi import Header, HTTPException

async def get_current_user(
    authorization: str | None = Header(default = None),
):
    """
    TODO:
    - Validate that an Authorization header exists
    - Reject missing/invalid headers
    - Return a user context (dict is fine)

    Args:
        authorization (str | None, optional): _description_. Defaults to Header(default = None).
    """
    pass