"""
Financial validation utilities for fraud investigation.
Includes Luhn algorithm validation, BIN classification, and deobfuscation.
"""
import re
from typing import Dict, Optional, Tuple, List


def is_valid_luhn(cc_number: str) -> bool:
    """
    Checks if a credit card number is valid according to the Luhn algorithm.
    
    Args:
        cc_number: The credit card number (can include dashes/spaces).
    
    Returns:
        True if valid, False otherwise.
    """
    # Sanitize: Remove all non-digit characters
    digits = [int(d) for d in str(cc_number) if d.isdigit()]
    
    # Check length (basic sanity check, usually 13-19 digits)
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    # Reverse the list of digits (we process from right to left)
    digits.reverse()
    
    # Double every second digit
    for i in range(1, len(digits), 2):
        digits[i] *= 2
        
        # If the result is > 9, subtract 9 (sum the digits of the product)
        if digits[i] > 9:
            digits[i] -= 9
    
    # Sum all digits
    total_sum = sum(digits)
    
    # Valid if the sum is a multiple of 10
    return total_sum % 10 == 0


def get_luhn_check_digit(partial_number: str) -> int:
    """
    Calculates the check digit (the last digit) for a given partial number.
    Useful when recovering partial data from logs.
    
    Args:
        partial_number: The first N-1 digits of a card.
    
    Returns:
        The required check digit to make the number valid.
    """
    # Sanitize
    digits = [int(d) for d in str(partial_number) if d.isdigit()]
    
    # Reverse to prepare for the algorithm
    digits.reverse()
    
    # In the partial sequence, we double the "odd" indices
    # (1st, 3rd, 5th from the right of the PARTIAL string)
    for i in range(0, len(digits), 2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    
    total_sum = sum(digits)
    
    # Calculate what we need to reach the next multiple of 10
    remainder = total_sum % 10
    if remainder == 0:
        return 0
    else:
        return 10 - remainder


def identify_issuer(cc_number: str) -> str:
    """
    Returns the network and potential issuer based on prefixes.
    Purely local; does not query external APIs (OPSEC safe).
    
    Args:
        cc_number: Credit card number (can include dashes/spaces).
    
    Returns:
        String describing the issuer/network.
    """
    s = ''.join([d for d in str(cc_number) if d.isdigit()])
    
    if not s:
        return "Unknown Issuer"
    
    # Major Networks
    if s.startswith('3') and len(s) == 15:
        return "Amex"
    if s.startswith('6011'):
        return "Discover"
    if s.startswith(('30', '36', '38')):
        return "Diners Club"
    
    # Specific BIN ranges (Examples - expand with data from your cases)
    bin_6 = s[:6]
    
    # Example placeholders - Real BIN lists are massive
    known_bins = {
        '414720': 'Chase (Signature Visa)',
        '414709': 'Capital One',
        '400022': 'Bank of America',
        '473702': 'Wells Fargo',
        '542418': 'Citibank',
        '434256': 'TD Bank',
        '411111': 'Visa Test',
        '555555': 'Mastercard Test'
    }
    
    if bin_6 in known_bins:
        return f"Visa/MC - {known_bins[bin_6]}"
    
    if s.startswith('4'):
        return "Visa (Generic)"
    if s.startswith('5'):
        return "Mastercard (Generic)"
    
    return "Unknown Issuer"


def deobfuscate_text(text: str) -> str:
    """
    Normalizes common obfuscation techniques used by fraudsters
    to hide IPs and emails from scrapers.
    
    Args:
        text: Text that may contain obfuscated indicators.
    
    Returns:
        Deobfuscated text ready for regex scanning.
    """
    # Handle "dot" variations
    text = re.sub(r'\s?\[\.\]\s?', '.', text)
    text = re.sub(r'\s?\(dot\)\s?', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\s?\[dot\]\s?', '.', text, flags=re.IGNORECASE)
    
    # Handle "at" variations (for emails)
    text = re.sub(r'\s?\[@\]\s?', '@', text)
    text = re.sub(r'\s?\(at\)\s?', '@', text, flags=re.IGNORECASE)
    text = re.sub(r'\s?\[at\]\s?', '@', text, flags=re.IGNORECASE)
    
    # Handle "hxxp" (common URL defanging)
    text = re.sub(r'hxxp', 'http', text, flags=re.IGNORECASE)
    text = re.sub(r'hxxps', 'https', text, flags=re.IGNORECASE)
    
    # Handle space-separated IPs (e.g., "192 . 168 . 1 . 1")
    text = re.sub(r'(\d+)\s+\.\s+(\d+)\s+\.\s+(\d+)\s+\.\s+(\d+)', r'\1.\2.\3.\4', text)
    
    return text


def validate_and_classify_credit_card(cc_number: str) -> Dict[str, any]:
    """
    Validates a credit card number using Luhn algorithm and classifies the issuer.
    
    Args:
        cc_number: Credit card number to validate.
    
    Returns:
        Dictionary with validation results and issuer information.
    """
    cleaned = ''.join([d for d in str(cc_number) if d.isdigit()])
    
    result = {
        'number': cleaned,
        'original': cc_number,
        'is_valid_luhn': False,
        'issuer': 'Unknown',
        'length': len(cleaned)
    }
    
    if cleaned:
        result['is_valid_luhn'] = is_valid_luhn(cleaned)
        result['issuer'] = identify_issuer(cleaned)
    
    return result

