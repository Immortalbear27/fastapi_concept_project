from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from app.models.schemas import ThreatVerdict, ThreatResponse
from app.analysis.threat_analysis import cpu_intensive_fingerprint

# This sets the absolutely basic requirements that a class needs:
@dataclass(frozen=True)
class AnalysisResult:
    """
    Output of a single analyser
    Each analyser can contribute:
    - Indicators
    - Score contributions
    """
    indicators: List[str]
    score: float
    
# This class defines the equivalent of an empty skeleton class, for use in later interpretations.
# It's considered as an abstract class, which is defined through the use of the ABC parameter.
# This effectively acts as a form of class definition, which defines the names of functions,
# but the actual interpretation is done at class inheritance time.
class BaseAnalyser(ABC):
    """
    Abstract base class defining the interfact for all analysers

    Args:
        ABC: N/A
    """
    
    @abstractmethod
    def analyse(self, payload: str):
        """
        Analyse payload and return a partial result
        """
        raise NotImplementedError
    
class KeywordAnalyser(BaseAnalyser):
    """
    Rule-based analyser that looks for suspicious keywords.

    Args:
        BaseAnalyser: N/A
    """
    
    def __init__(self):
        self.rules = {
            "powershell": 0.9,
            "sus": 0.7,
            "mid": 0.5,
            "low": 0.1
        }
        
    def analyse(self, payload: str):
        """
        Normalises payload, finds matched keywords, chooses a scoring rule, then returns Analysis Result
        """
        # Normalise the payload for better rule-based matching:
        normalisedPayload = payload.lower()
        # Find matched keywords:
        indicators = []
        scores = []
        for indicator, score in self.rules.items():
            if indicator in normalisedPayload:
                indicators.append(indicator)
                scores.append(score)
                
        if len(scores) > 0:
            maxScore = max(scores)
        else:
            maxScore = 0.0
            
        return AnalysisResult(indicators, maxScore)
    
class FingerprintAnalyser(BaseAnalyser):
    """
    Generates a fingerprint for the payload.
    CPU-bound process.

    Args:
        BaseAnalyser: N/A
    """
    def __init__(self, rounds: int = 50000):
        self.rounds = rounds
        
    def analyse(self, payload: str):
        """
        Call the CPU-intensive function, include a short fingerprint, then return small score contribution.

        Args:
            payload (str): Payload data from the network traffic received from user by server.
        """
        fingerprint = cpu_intensive_fingerprint(payload, self.rounds)
        indicators = [f"fingerprint:{fingerprint[:12]}"]
        score = 0.0
        return AnalysisResult(indicators, score)
    
class ThreatPipeline:
    """
    Orchestrates multiple analysers and returns a final ThreatResponse.
    """
    
    def __init__(self, analysers: List[BaseAnalyser]):
        self.analysers = analysers
        
    def _classify(self, risk_score: float):
        """
        Maps thresholds to ThreatVerdict.

        Args:
            risk_score (float): The score that measures risk, between 0.0 and 1.0.
        """
        
        if risk_score < 0.0 or risk_score > 1.0:
            raise ValueError
        
        if risk_score <= 0.3:
            return ThreatVerdict.benign
        elif risk_score <=0.7 and risk_score > 0.3:
            return ThreatVerdict.suspicious
        else:
            return ThreatVerdict.malicious
    
    def run(self, payload: str):
        """
        Runs all analysers and aggregates the results.

        Args:
            payload (str): The payload data received from network traffic sent by user.
        """
        
        all_indicators = []
        scores = []
        for analyser in self.analysers:
            result = analyser.analyse(payload)
            all_indicators.extend(result.indicators)
            scores.append(result.score)
        
        risk_score = max(scores, default = 0.0)
        
        # Get the classification of the risk:
        classLabel = self._classify(risk_score)
        
        # Return all necessary information:
        return ThreatResponse(risk_score, classLabel, all_indicators)