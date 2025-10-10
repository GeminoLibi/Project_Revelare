import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field

from revelare.config.config import Config
from revelare.utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class EnhancedIndicator:
    value: str
    category: str
    context: str
    file_name: str
    line_number: int
    position: int = 0
    timestamp: Optional[str] = None
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    protocol: Optional[str] = None
    user_agent: Optional[str] = None
    host_header: Optional[str] = None
    session_id: Optional[str] = None
    confidence_score: float = 1.0
    is_relevant: bool = True
    metadata: Dict[str, str] = field(default_factory=dict)

class DataEnhancer:
    def __init__(self):
        self.filter_patterns = Config.FILTER_PATTERNS
        self.regex_patterns = Config.REGEX_PATTERNS
        self.compiled_filters = self._compile_filters()
        
    def _compile_filters(self) -> Dict[str, List[re.Pattern]]:
        compiled = {}
        for category, patterns in self.filter_patterns.items():
            compiled[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
        return compiled
    
    def is_irrelevant(self, indicator: EnhancedIndicator) -> bool:
        if not indicator:
            return True
        
        value = indicator.value
        category = indicator.category
        
        filter_map = {
            'IPv4': 'Common_Irrelevant_IPs',
            'URLs': 'Common_Irrelevant_URLs',
            'Email_Addresses': 'Common_Irrelevant_Emails'
        }
        
        if category in filter_map:
            for pattern in self.compiled_filters.get(filter_map[category], []):
                if pattern.search(value):
                    logger.debug(f"Filtered out irrelevant {category}: {value}")
                    return True

        if len(value) < 5 and category not in ['IPv4']:
             return True

        if value.lower() in ['null', 'none', 'undefined', 'n/a']:
            return True
        
        return False

    def create_enhanced_indicator(self, indicator: str, category: str, context: str, file_name: str, position: int) -> EnhancedIndicator:
        return EnhancedIndicator(
            value=indicator,
            category=category,
            context=context,
            file_name=file_name,
            line_number=0,
            position=position
        )