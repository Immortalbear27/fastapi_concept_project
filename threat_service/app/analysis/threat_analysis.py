from enum import Enum
from typing import List, Tuple

from app.models.schemas import ThreatResponse, ThreatVerdict

class SuspiciousKeywords(Enum):
    """
    Define a list of suspicious words with associated risk scores, that can be used to indicate whether
    a payload of a network traffic is suspicious, with varying levels of certainty

    Args:
        Enum (_type_): Enum argument, no more to say
    """
    # Setting the suspicious words and their respective risk scores:
    powershell = ("powershell", 0.9),
    sus = ("sus", 0.6),
    tester = ("tester", 0.2),
    other = ("other", 0.1)
    
    # Used for later access to the keywords and values in the Enum:
    def __init__(self, keyword: str, score: float):
        self.keyword = keyword
        self.score = score
        

def analyse_payload(payload: str) -> Tuple[List[str], List[float]]:
    # Initialisation of arrays:
    indicators = []
    scores = []
     
    # Check for any suspicious words, and get their associated values:
    # Breakdown of section:
    # - For each suspicious word in the list:
    # - - If it ends up being in the payload:
    # - - - Add the word to the list of indicators
    # - - - Add the associated score to the list of scores
    for indicator in SuspiciousKeywords:
        if indicator.keyword in payload:
            indicators.append(indicator.keyword)
            scores.append(indicator.score)
    
    # Return the lists of indicators and scores:
    return indicators, scores

def classify_risk(risk_score: float) -> str:
    """
    Classifies the risk of the payload information based on the highest risk score collected.

    Args:
        risk_score (float): The risk score that determines how risky the payload data is.

    Raises:
        Exception: If, for some goddamn reason, a bad entry gets in here, then it will throw an error.

    Returns:
        str: Classification label of the risk score
    """
    # Determine the level of risk, and assign the appropriate label:
    if risk_score <= 0.3:
        return "benign"
    elif risk_score <= 0.7 and risk_score > 0.3:
        return "suspicious"
    elif risk_score <= 1.0 and risk_score > 0.7:
        return "malicious"
    else:
        # This shouldn't trigger. Ever. If it somehow does, you'll know where from:
        raise Exception ("How in the hell did you trigger this...")
    
def analyse_threat(payload_data: str):
    """
    Analyses the threat and returns the collated data regarding the payload.

    Args:
        payload_data (str): The payload of the network traffic that has been received.

    Returns:
        ThreatResponse: A ThreatResponse detailing a structured threat assessment
    """
    # Initialise arrays:
    IndicatorList = []
    ScoreList = []
    # Obtain lists of indicators and scores:
    IndicatorList, ScoreList = analyse_payload(payload_data)
    # Get highest risk rating:
    MaxRiskScore = max(ScoreList)
    # Get the classification label:
    ClassLabel = classify_risk(MaxRiskScore)
    return ThreatResponse(
        risk_score = MaxRiskScore,
        classification_label = ClassLabel,
        indicators = IndicatorList
    )
    