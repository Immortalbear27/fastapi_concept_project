from pydantic import BaseModel
from typing import List

class ThreatRequest(BaseModel):
    # TODO:
    # - source_ip
    # - destination_ip
    # - payload (string or bytes)
    pass

class ThreatResponse(BaseModel):
    # TODO:
    # - risks_score (float)
    # - verdict (str)
    # - indicators (list of strings)
    pass