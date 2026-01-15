from pydantic import BaseModel, IPvAnyAddress, Field
from typing import List
from enum import Enum

# Identifying good schema:
# In this case, there is a user interaction and a system response
# The user interaction is sending network traffic metadata, as well as the payload content
# The system then receives that information, and analyses it and returns a structured threat assessment.
# As such, a sample sentence describing the model's schema would be:
# 'The client sends network traffic metadata and payload content, so that the service can analyse it
# and return a structured threat assessment'
# This would then break down into what is below:

# NOTE: This (ThreatVerdict) is used to define acceptable data types for ThreatResponse.classification_label
# It is not inherently required for a schema, but is a clean way of representing multiple strings at once.

class ThreatVerdict(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"

class ThreatRequest(BaseModel):
    # TODO:
    # - source_ip
    # Simple implementation - source_ip: str
    # Correct implementation:
    source_ip: IPvAnyAddress
    # - destination_ip
    # Same as above:
    destination_ip: IPvAnyAddress
    # - payload (string or bytes)
    payload_data: str = Field(..., min_length = 1, max_length= 100000)

class ThreatResponse(BaseModel):
    # TODO:
    # - risks_score (float)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    # - verdict (str)
    classification_label: ThreatVerdict
    # - indicators (list of strings)
    indicators: List[str]