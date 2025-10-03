#!/usr/bin/env python3
"""
Enhanced Data Extraction and Filtering for Legal Warrant Requirements.

This module provides advanced data enhancement and filtering capabilities
specifically designed to meet legal warrant requirements for digital forensics
and incident response. It includes intelligent filtering to remove irrelevant
indicators and enhance relevant ones with additional metadata.

Key Features:
- Intelligent indicator filtering based on relevance
- Enhanced metadata extraction for legal documentation
- IP address geolocation and classification
- Email domain analysis and filtering
- URL categorization and threat assessment
- File path analysis and context extraction
- Temporal analysis and timestamp validation
- Network context extraction
- Legal warrant format preparation

Filtering Capabilities:
- Removes test/example data (example.com, test.com, etc.)
- Filters out localhost and loopback addresses
- Identifies and removes common false positives
- Preserves relevant indicators with high confidence
- Maintains audit trail for legal compliance

Data Enhancement:
- Adds geographical information for IP addresses
- Extracts network context and relationships
- Validates timestamps and temporal data
- Adds confidence scores for indicators
- Generates summaries for legal documentation

Author: Project Revelare Team
Version: 2.1
License: MIT
"""

import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from config import Config
from logger import get_logger
from constants import *

logger = get_logger()

@dataclass
class EnhancedIndicator:
    """Enhanced indicator with metadata for legal warrant requirements"""
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
    metadata: Dict[str, str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class DataEnhancer:
    """Enhanced data extraction and filtering system for legal warrant requirements"""
    
    def __init__(self):
        self.filter_patterns = Config.FILTER_PATTERNS
        self.regex_patterns = Config.REGEX_PATTERNS
        self.compiled_filters = self._compile_filters()
        self.compiled_patterns = self._compile_patterns()
        
    def _compile_filters(self) -> Dict[str, List[re.Pattern]]:
        """Compile filter patterns for performance"""
        compiled = {}
        for category, patterns in self.filter_patterns.items():
            compiled[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        return compiled
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for performance"""
        compiled = {}
        for category, pattern in self.regex_patterns.items():
            try:
                compiled[category] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.error(f"Invalid regex pattern for {category}: {e}")
        return compiled
    
    def extract_enhanced_indicators(self, text: str, file_name: str) -> List[EnhancedIndicator]:
        """Extract indicators with enhanced metadata for legal warrant requirements"""
        indicators = []
        
        for line_num, line in enumerate(text.splitlines(), 1):
            line_indicators = self._process_line(line, file_name, line_num)
            indicators.extend(line_indicators)
        
        # Filter out irrelevant indicators
        filtered_indicators = self._filter_irrelevant_indicators(indicators)
        
        # Enhance with additional metadata
        enhanced_indicators = self._enhance_with_metadata(filtered_indicators, text)
        
        return enhanced_indicators
    
    def _process_line(self, line: str, file_name: str, line_num: int) -> List[EnhancedIndicator]:
        """Process a single line for indicators"""
        indicators = []
        
        for category, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(line):
                value = match.group(0)
                
                # Extract additional context
                context = self._extract_context(line, match)
                
                # Create enhanced indicator
                indicator = EnhancedIndicator(
                    value=value,
                    category=category,
                    context=context,
                    file_name=file_name,
                    line_number=line_num,
                    metadata={}
                )
                
                # Extract specific metadata based on category
                self._extract_category_metadata(indicator, line, match)
                
                indicators.append(indicator)
        
        return indicators
    
    def _extract_context(self, line: str, match: re.Match) -> str:
        """Extract context around the match"""
        start = max(0, match.start() - 100)
        end = min(len(line), match.end() + 100)
        context = line[start:end].strip()
        
        if len(context) > 200:
            context = f"...{context}..."
        
        return context
    
    def _extract_category_metadata(self, indicator: EnhancedIndicator, line: str, match: re.Match):
        """Extract category-specific metadata"""
        category = indicator.category
        value = indicator.value
        
        # Extract timestamps from the line
        timestamp = self._extract_timestamp(line)
        if timestamp:
            indicator.timestamp = timestamp
        
        # Extract port information
        if 'Port' in category or ':' in value:
            ports = self._extract_ports(line, value)
            if ports:
                indicator.source_port = ports.get('source')
                indicator.destination_port = ports.get('destination')
        
        # Extract protocol information
        protocol = self._extract_protocol(line)
        if protocol:
            indicator.protocol = protocol
        
        # Extract HTTP headers
        if 'HTTP' in line or 'http' in line:
            user_agent = self._extract_user_agent(line)
            if user_agent:
                indicator.user_agent = user_agent
            
            host_header = self._extract_host_header(line)
            if host_header:
                indicator.host_header = host_header
        
        # Extract session information
        session_id = self._extract_session_id(line)
        if session_id:
            indicator.session_id = session_id
        
        # Calculate confidence score
        indicator.confidence_score = self._calculate_confidence_score(indicator, line)
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from line"""
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{3})?([+-]\d{2}:\d{2}|Z)?',
            r'\b\d{10}(\.\d{3})?\b',
            r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        
        return None
    
    def _extract_ports(self, line: str, value: str) -> Dict[str, str]:
        """Extract source and destination ports"""
        ports = {}
        
        # Look for port patterns in the line
        port_pattern = r':(\d{1,5})\b'
        port_matches = re.findall(port_pattern, line)
        
        if port_matches:
            if len(port_matches) >= 2:
                ports['source'] = port_matches[0]
                ports['destination'] = port_matches[1]
            else:
                ports['source'] = port_matches[0]
        
        return ports
    
    def _extract_protocol(self, line: str) -> Optional[str]:
        """Extract protocol from line"""
        protocol_patterns = [
            r'(HTTP/\d\.\d)',
            r'(FTP)',
            r'(SSH)',
            r'(SMTP)',
            r'(POP3)',
            r'(IMAP)',
            r'(DNS)',
            r'(HTTPS)',
        ]
        
        for pattern in protocol_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_user_agent(self, line: str) -> Optional[str]:
        """Extract User-Agent from line"""
        match = re.search(r'User-Agent:\s*([^\r\n]+)', line, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_host_header(self, line: str) -> Optional[str]:
        """Extract Host header from line"""
        match = re.search(r'Host:\s*([^\r\n]+)', line, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_session_id(self, line: str) -> Optional[str]:
        """Extract session ID from line"""
        patterns = [
            r'[Ss]ession[_-]?[Ii][Dd]:\s*([A-Za-z0-9+/=]+)',
            r'[Cc]ookie:\s*[^;]*session[_-]?id=([A-Za-z0-9+/=]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _calculate_confidence_score(self, indicator: EnhancedIndicator, line: str) -> float:
        """Calculate confidence score for the indicator"""
        score = 1.0
        
        # Reduce score for common false positives
        if indicator.category == 'IPv4':
            try:
                ip = ipaddress.ip_address(indicator.value)
                if ip.is_private or ip.is_loopback:
                    score *= 0.8
                if ip.is_multicast or ip.is_reserved:
                    score *= 0.6
            except ValueError:
                score *= 0.3
        
        # Increase score for indicators with timestamps
        if indicator.timestamp:
            score *= 1.2
        
        # Increase score for indicators with port information
        if indicator.source_port or indicator.destination_port:
            score *= 1.1
        
        # Increase score for indicators with protocol information
        if indicator.protocol:
            score *= 1.1
        
        return min(score, 2.0)  # Cap at 2.0
    
    def _filter_irrelevant_indicators(self, indicators: List[EnhancedIndicator]) -> List[EnhancedIndicator]:
        """Filter out irrelevant indicators based on patterns"""
        filtered = []
        
        for indicator in indicators:
            if self._is_relevant_indicator(indicator):
                filtered.append(indicator)
            else:
                indicator.is_relevant = False
                logger.debug(f"Filtered out irrelevant indicator: {indicator.value}")
        
        return filtered
    
    def _is_relevant_indicator(self, indicator: EnhancedIndicator) -> bool:
        """Check if indicator is relevant based on filtering patterns"""
        value = indicator.value
        category = indicator.category
        
        # Check category-specific filters
        if 'IP' in category:
            for pattern in self.compiled_filters.get('Common_Irrelevant_IPs', []):
                if pattern.match(value):
                    return False
        
        elif 'URL' in category:
            for pattern in self.compiled_filters.get('Common_Irrelevant_URLs', []):
                if pattern.match(value):
                    return False
        
        elif 'Email' in category:
            for pattern in self.compiled_filters.get('Common_Irrelevant_Emails', []):
                if pattern.match(value):
                    return False
        
        elif 'Port' in category:
            for pattern in self.compiled_filters.get('Common_Irrelevant_Ports', []):
                if pattern.match(value):
                    return False
        
        # Additional relevance checks
        if len(value) < 3:  # Too short
            return False
        
        if value.lower() in ['null', 'none', 'undefined', 'n/a', 'na']:
            return False
        
        # Check for test/example data
        if any(test_word in value.lower() for test_word in ['test', 'example', 'sample', 'demo']):
            return False
        
        return True
    
    def _enhance_with_metadata(self, indicators: List[EnhancedIndicator], full_text: str) -> List[EnhancedIndicator]:
        """Enhance indicators with additional metadata from the full text"""
        for indicator in indicators:
            # Add file-level metadata
            indicator.metadata['extraction_time'] = datetime.now(timezone.utc).isoformat()
            indicator.metadata['file_size'] = str(len(full_text))
            
            # Add network context if available
            if indicator.category in ['IPv4', 'IPv6', 'IPv4_with_Port', 'IPv6_with_Port']:
                self._add_network_context(indicator, full_text)
            
            # Add temporal context
            if indicator.timestamp:
                indicator.metadata['timestamp_confidence'] = self._assess_timestamp_confidence(indicator.timestamp)
        
        return indicators
    
    def _add_network_context(self, indicator: EnhancedIndicator, full_text: str):
        """Add network context to IP indicators"""
        # Look for related network information in the text
        context_lines = []
        for line in full_text.splitlines():
            if indicator.value in line:
                context_lines.append(line.strip())
        
        if context_lines:
            indicator.metadata['network_context'] = '; '.join(context_lines[:3])  # Limit to 3 lines
    
    def _assess_timestamp_confidence(self, timestamp: str) -> str:
        """Assess confidence in timestamp format"""
        if re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', timestamp):
            return 'high'
        elif re.match(r'\b\d{10}(\.\d{3})?\b', timestamp):
            return 'medium'
        else:
            return 'low'
    
    def group_indicators_by_connection(self, indicators: List[EnhancedIndicator]) -> Dict[str, List[EnhancedIndicator]]:
        """Group indicators by network connection for legal warrant requirements"""
        connections = {}
        
        for indicator in indicators:
            if indicator.category in ['IPv4', 'IPv6', 'IPv4_with_Port', 'IPv6_with_Port']:
                # Create connection key
                connection_key = f"{indicator.value}_{indicator.source_port}_{indicator.destination_port}"
                
                if connection_key not in connections:
                    connections[connection_key] = []
                
                connections[connection_key].append(indicator)
        
        return connections
    
    def generate_legal_summary(self, indicators: List[EnhancedIndicator]) -> Dict[str, any]:
        """Generate summary suitable for legal warrant requirements"""
        summary = {
            'total_indicators': len(indicators),
            'unique_ips': len(set(i.value for i in indicators if 'IP' in i.category)),
            'unique_emails': len(set(i.value for i in indicators if 'Email' in i.category)),
            'unique_urls': len(set(i.value for i in indicators if 'URL' in i.category)),
            'time_range': self._calculate_time_range(indicators),
            'ports_used': self._extract_ports_used(indicators),
            'protocols_used': self._extract_protocols_used(indicators),
            'high_confidence_indicators': len([i for i in indicators if i.confidence_score > 1.5]),
            'indicators_with_timestamps': len([i for i in indicators if i.timestamp]),
            'indicators_with_ports': len([i for i in indicators if i.source_port or i.destination_port]),
        }
        
        return summary
    
    def _calculate_time_range(self, indicators: List[EnhancedIndicator]) -> Dict[str, str]:
        """Calculate time range from indicators with timestamps"""
        timestamps = [i.timestamp for i in indicators if i.timestamp]
        
        if not timestamps:
            return {'earliest': 'N/A', 'latest': 'N/A'}
        
        # Simple string comparison for now - could be enhanced with proper date parsing
        timestamps.sort()
        return {'earliest': timestamps[0], 'latest': timestamps[-1]}
    
    def _extract_ports_used(self, indicators: List[EnhancedIndicator]) -> List[str]:
        """Extract all ports used"""
        ports = set()
        for indicator in indicators:
            if indicator.source_port:
                ports.add(indicator.source_port)
            if indicator.destination_port:
                ports.add(indicator.destination_port)
        return sorted(list(ports))
    
    def _extract_protocols_used(self, indicators: List[EnhancedIndicator]) -> List[str]:
        """Extract all protocols used"""
        protocols = set()
        for indicator in indicators:
            if indicator.protocol:
                protocols.add(indicator.protocol)
        return sorted(list(protocols))
    
    def create_enhanced_indicator(self, indicator: str, category: str, context: str, file_name: str, position: int) -> EnhancedIndicator:
        """Create an enhanced indicator from basic data"""
        return EnhancedIndicator(
            value=indicator,
            category=category,
            context=context,
            file_name=file_name,
            line_number=0,  # Will be calculated later if needed
            position=position,
            metadata={}
        )
    
    def is_irrelevant(self, indicator: EnhancedIndicator) -> bool:
        """Check if an indicator is irrelevant"""
        if not indicator:
            return True
        return not self._is_relevant_indicator(indicator)