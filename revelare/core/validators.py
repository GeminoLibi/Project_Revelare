#!/usr/bin/env python3
"""
Data Validation Module for Project Revelare
Contains validation functions for various data types and indicators.
"""

import re
from typing import Optional, Dict, Any
from revelare.utils.logger import get_logger

logger = get_logger(__name__)


class DataValidator:
    """Central class for data validation operations."""

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email address format."""
        if not email or len(email) < 5:
            return False
        if not email[0].isalnum() or '@' not in email or '.' not in email.split('@')[1]:
            return False
        return True

    @staticmethod
    def is_valid_phone(phone: str) -> bool:
        """Validate US phone number format."""
        if not phone:
            return False

        # Clean the phone number - remove all non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', phone)

        # Handle different formats
        if cleaned.startswith('+1'):
            cleaned = cleaned[2:]
        elif cleaned.startswith('1') and len(cleaned) in [10, 11]:
            cleaned = cleaned[1:]

        # Must be exactly 10 digits
        if len(cleaned) != 10 or not cleaned.isdigit():
            return False

        # First digit of the area code must be 2-9 (not 0 or 1)
        if int(cleaned[0]) < 2:
            return False

        # Additional area code validation
        area_code = cleaned[:3]
        return DataValidator.is_valid_area_code(area_code)

    @staticmethod
    def is_valid_area_code(area_code: str) -> bool:
        """Validate area code format and attempt API validation."""
        if not area_code.isdigit() or len(area_code) != 3:
            return False

        # Basic US area code rules
        first_digit = int(area_code[0])
        second_digit = int(area_code[1])

        # Area code cannot start with 0 or 1
        if first_digit in [0, 1]:
            return False

        # Check for invalid area codes (test numbers, etc.)
        invalid_codes = ['555', '000', '111', '222', '333', '444', '666', '777', '888', '999']
        if area_code in invalid_codes:
            return False

        # Additional validation: area codes ending in 00 or 11 are typically invalid
        if second_digit == 0 and int(area_code[2]) == 0:
            return False
        if second_digit == 1 and int(area_code[2]) == 1:
            return False

        return True

    @staticmethod
    def is_valid_ssn(ssn: str) -> bool:
        """Validate Social Security Number format."""
        if not ssn:
            return False
        cleaned = re.sub(r'[^\d]', '', ssn)
        if len(cleaned) != 9:
            return False
        if cleaned.startswith('000') or cleaned.startswith('666') or int(cleaned[:3]) >= 900:
            return False
        if cleaned[3:5] == '00':
            return False
        if cleaned[5:] == '0000':
            return False
        return True

    @staticmethod
    def classify_ip(ip: str) -> str:
        """Classify IP address type."""
        try:
            if ':' in ip:
                ip = ip.split(':')[0]
            parts = ip.split('.')
            if len(parts) != 4:
                return "Invalid"
            octets = [int(part) for part in parts]
            if any(not 0 <= octet <= 255 for octet in octets):
                return "Invalid"
            first_octet = octets[0]

            if first_octet == 0:
                return "Reserved/Bogus"
            elif first_octet == 10:
                return "Private"
            elif first_octet == 127:
                return "Loopback"
            elif first_octet == 169 and octets[1] == 254:
                return "Link-Local"
            elif first_octet == 172 and 16 <= octets[1] <= 31:
                return "Private"
            elif first_octet == 192 and octets[1] == 168:
                return "Private"
            elif 224 <= first_octet <= 239:
                return "Multicast"
            elif 240 <= first_octet <= 255:
                return "Reserved"
            else:
                return "Public"
        except Exception:
            return "Invalid"

    @staticmethod
    def is_valid_routing_number(routing_number: str) -> bool:
        """Validate US bank routing number and check against known banks."""
        if not routing_number or len(routing_number) != 9 or not routing_number.isdigit():
            return False

        # Routing number validation algorithm
        digits = [int(d) for d in routing_number]
        checksum = (3 * (digits[0] + digits[3] + digits[6]) +
                   7 * (digits[1] + digits[4] + digits[7]) +
                   (digits[2] + digits[5] + digits[8]))

        # Must pass checksum validation
        if checksum % 10 != 0:
            return False

        # Check against known routing numbers database
        from revelare.config.config import Config
        return routing_number in Config.ROUTING_NUMBERS

    @staticmethod
    def get_routing_number_info(routing_number: str) -> Optional[str]:
        """Get bank information for a routing number."""
        from revelare.config.config import Config
        return Config.ROUTING_NUMBERS.get(routing_number)