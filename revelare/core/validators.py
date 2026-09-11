import re
from typing import Optional, Dict, Any
from revelare.utils.logger import get_logger

logger = get_logger(__name__)

class DataValidator:
    @staticmethod
    def is_valid_email(email: str) -> bool:
        if not email or len(email) < 5:
            return False
        if not email[0].isalnum() or '@' not in email or '.' not in email.split('@')[1]:
            return False
        return True

    @staticmethod
    def is_valid_phone(phone: str) -> bool:
        if not phone:
            return False
        cleaned = re.sub(r'[^\d+]', '', phone)
        if cleaned.startswith('+1'):
            cleaned = cleaned[2:]
        elif cleaned.startswith('1') and len(cleaned) in [10, 11]:
            cleaned = cleaned[1:]
        
        if len(cleaned) != 10 or not cleaned.isdigit():
            return False
        
        if int(cleaned[0]) < 2:
            return False
        
        return DataValidator.is_valid_area_code(cleaned[:3])

    @staticmethod
    def is_valid_area_code(area_code: str) -> bool:
        if not area_code.isdigit() or len(area_code) != 3:
            return False
        
        first_digit = int(area_code[0])
        if first_digit in [0, 1]:
            return False
        
        invalid_codes = ['555', '000', '111', '222', '333', '444', '666', '777', '888', '999']
        if area_code in invalid_codes:
            return False
            
        return True

    @staticmethod
    def is_valid_ssn(ssn: str) -> bool:
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
            if first_octet == 0: return "Reserved/Bogus"
            elif first_octet == 10: return "Private"
            elif first_octet == 127: return "Loopback"
            elif first_octet == 169 and octets[1] == 254: return "Link-Local"
            elif first_octet == 172 and 16 <= octets[1] <= 31: return "Private"
            elif first_octet == 192 and octets[1] == 168: return "Private"
            elif 224 <= first_octet <= 239: return "Multicast"
            elif 240 <= first_octet <= 255: return "Reserved"
            else: return "Public"
        except Exception:
            return "Invalid"

    @staticmethod
    def is_valid_routing_number(routing_number: str) -> bool:
        if not routing_number or len(routing_number) != 9 or not routing_number.isdigit():
            return False

        digits = [int(d) for d in routing_number]
        checksum = (3 * (digits[0] + digits[3] + digits[6]) +
                   7 * (digits[1] + digits[4] + digits[7]) +
                   (digits[2] + digits[5] + digits[8]))

        if checksum % 10 != 0:
            return False

        from revelare.config.config import Config
        return routing_number in Config.ROUTING_NUMBERS

    @staticmethod
    def get_routing_number_info(routing_number: str) -> Optional[str]:
        from revelare.config.config import Config
        return Config.ROUTING_NUMBERS.get(routing_number)

    _PERSON_NAME_STOPWORDS = {
        'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
        'september', 'october', 'november', 'december',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        'north', 'south', 'east', 'west', 'central',
        'united', 'states', 'america', 'county', 'department', 'bureau', 'office',
        'court', 'police', 'sheriff', 'district', 'federal', 'national',
        'international', 'general', 'special', 'senior', 'junior', 'agent', 'officer',
        'detective', 'investigator', 'attorney', 'counsel', 'manager', 'director',
        'administrator', 'supervisor', 'services', 'systems', 'solutions', 'company',
        'corporation', 'limited', 'inc', 'llc', 'ltd', 'group', 'team', 'support',
        'customer', 'account', 'security', 'privacy', 'policy', 'terms', 'conditions',
        'copyright', 'reserved', 'true', 'false', 'null', 'none', 'unknown', 'default',
        'admin', 'user', 'guest', 'system', 'server',
        'client', 'mobile', 'android', 'iphone', 'windows', 'google', 'microsoft',
        'apple', 'amazon', 'facebook', 'instagram', 'whatsapp', 'telegram', 'signal',
        'yahoo', 'outlook', 'gmail', 'hotmail',
        'new', 'old', 'san', 'los', 'las', 'fort', 'mount', 'saint', 'lake', 'port',
        'grand', 'little', 'big', 'upper', 'lower',
        'street', 'road', 'avenue', 'drive', 'lane', 'boulevard', 'place', 'way',
        'circle', 'parkway', 'highway', 'route', 'box', 'suite', 'floor', 'building',
        'apartment', 'apt',
        'ave', 'blvd', 'ln', 'rd', 'hwy', 'estates', 'village', 'meadows',
        'dear', 'sir', 'madam',
        'coming', 'soon', 'cover', 'reveal', 'keyword', 'research',
        'recovery', 'wellness', 'campaign', 'publishing',
    }

    _PERSON_NAME_SUFFIX_RE = re.compile(r"^(?:Jr|Sr|II|III|IV)\.?$", re.IGNORECASE)
    _PERSON_NAME_INITIAL_RE = re.compile(r"^[A-Z]\.?$")

    @staticmethod
    def is_valid_person_name(name: str) -> bool:
        """
        Conservative person-name check: First Last, optional middle initial,
        optional Jr/Sr/III. Reject 3+ title-case words that are not that shape.
        """
        if not name or len(name) < 5 or len(name) > 80:
            return False
        if any(ch.isdigit() for ch in name):
            return False
        if name.isupper():
            return False
        if '@' in name or '://' in name or '\\' in name:
            return False

        parts = re.split(r'\s+', name.strip())
        if len(parts) < 2 or len(parts) > 4:
            return False

        core = list(parts)
        if DataValidator._PERSON_NAME_SUFFIX_RE.match(core[-1]):
            core = core[:-1]
        if len(core) == 2:
            pass
        elif len(core) == 3 and DataValidator._PERSON_NAME_INITIAL_RE.match(core[1]):
            pass
        else:
            return False

        stopwords = DataValidator._PERSON_NAME_STOPWORDS
        for part in core:
            cleaned = part.strip(".'-")
            if len(cleaned) < 1:
                return False
            if DataValidator._PERSON_NAME_INITIAL_RE.match(part):
                continue
            if len(cleaned) < 2:
                return False
            token_ok = bool(
                re.match(r"^[A-Z][a-z']+$", part)
                or re.match(r"^[A-Z][a-z]+-[A-Z][a-z]+$", part)
                or re.match(r"^[A-Z][a-z]*'[A-Z][a-z]+$", part)
            )
            if not token_ok:
                return False
            token_key = cleaned.replace("-", " ").replace("'", "").lower()
            if cleaned.lower() in stopwords or token_key in stopwords:
                return False

        joined_lower = name.lower()
        org_markers = (
            ' department', ' bureau', ' office', ' court', ' police',
            ' llc', ' inc', ' corporation', ' company', ' university',
            ' foundation', ' association', ' services', ' systems',
        )
        if any(marker in joined_lower for marker in org_markers):
            return False

        return True