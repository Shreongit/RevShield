from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict

class AnalysisContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw_url: str
    normalized_url: str
    domain: str
    ip_address: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = {}
    response_body: Optional[str] = None
    response_cookies: List[Dict[str, Any]] = []
    redirect_history: List[Dict[str, Any]] = []
    third_party_resources: List[str] = []

class BaseAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @abstractmethod
    async def analyze(self, context: AnalysisContext) -> Dict[str, Any]:
        """Execute the analyzer logic and return structured findings."""
        pass
