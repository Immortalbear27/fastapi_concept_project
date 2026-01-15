from pydantic import BaseModel
from typing import List

# Identifying good schema:
# In this case, there is a user interaction and a system response
# The user interaction is sending network traffic metadata, as well as the payload content
# The system then receives that information, and analyses it and returns a structured threat assessment.
# As such, a sample sentence describing the model's schema would be:
# 'The client sends network traffic metadata and payload content, so that the service can analyse it
# and return a structured threat assessment'
# This would then break down into what is below:

class ThreatRequest(BaseModel):
    # TODO:
    # - source_ip
    source_ip: str
    # - destination_ip
    destination_ip: str
    # - payload (string or bytes)
    payload_data: str

class ThreatResponse(BaseModel):
    # TODO:
    # - risks_score (float)
    risk_score: float
    # - verdict (str)
    classification_label: str
    # - indicators (list of strings)
    indicators: List[str]