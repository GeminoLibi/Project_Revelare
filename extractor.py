#!/usr/bin/env python3
"""
Enhanced data extraction module for Project Revelare.
"""

import os
import re
import time
from typing import Dict, List, Any
from urllib.parse import urlparse
from config import Config
from logger import get_logger, RevelareLogger
from security import SecurityValidator, InputValidator
from data_enhancer import DataEnhancer, EnhancedIndicator
import ipaddress
import datetime

logger = get_logger(__name__)
revelare_logger = RevelareLogger 
enhancer = DataEnhancer()

def is_valid_email(email: str) -> bool:
    if not email or len(email) < 5: return False
    if not email[0].isalnum() or '@' not in email or '.' not in email.split('@')[1]: return False
    return True 

def is_valid_phone(phone: str) -> bool:
    if not phone: return False
    
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
    return is_valid_area_code(area_code)

def is_valid_area_code(area_code: str) -> bool:
    try:
        import requests
        import time
        
        # Rate limiting
        if not hasattr(is_valid_area_code, 'last_call'):
            is_valid_area_code.last_call = 0
        
        current_time = time.time()
        if current_time - is_valid_area_code.last_call < 0.1:  # 100ms rate limit
            time.sleep(0.1 - (current_time - is_valid_area_code.last_call))
        
        # API call to validate area code
        response = requests.get(f"https://api.areacodeapi.com/v1/area/{area_code}", timeout=5)
        is_valid_area_code.last_call = time.time()
        
        if response.status_code == 200:
            data = response.json()
            return data.get('valid', False)
        else:
            # Fallback to basic validation if API fails
            return validate_area_code_fallback(area_code)
            
    except Exception as e:
        logger.debug(f"Area code API validation failed for {area_code}: {e}")
        return validate_area_code_fallback(area_code)

def enrich_area_code(area_code: str) -> Dict[str, Any]:
    try:
        import requests
        import time
        
        # Rate limiting
        if not hasattr(enrich_area_code, 'last_call'):
            enrich_area_code.last_call = 0
        
        current_time = time.time()
        if current_time - enrich_area_code.last_call < 0.1:  # 100ms rate limit
            time.sleep(0.1 - (current_time - enrich_area_code.last_call))
        
        # API call to get area code information
        response = requests.get(f"https://api.areacodeapi.com/v1/area/{area_code}", timeout=5)
        enrich_area_code.last_call = time.time()
        
        if response.status_code == 200:
            data = response.json()
            if data.get('valid', False):
                return {
                    'area_code': area_code,
                    'state': data.get('state', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'country': data.get('country', 'US'),
                    'source': 'areacodeapi.com'
                }
            else:
                return {
                    'area_code': area_code,
                    'error': 'Invalid area code',
                    'source': 'areacodeapi.com'
                }
        else:
            # Fallback to local area code database
            return enrich_area_code_fallback(area_code)
            
    except Exception as e:
        logger.debug(f"Area code enrichment API failed for {area_code}: {e}")
        return enrich_area_code_fallback(area_code)

def enrich_area_code_fallback(area_code: str) -> Dict[str, Any]:
    # Common US area codes with their locations
    area_code_data = {
        '803': {'state': 'South Carolina', 'city': 'Columbia', 'timezone': 'EST'},
        '212': {'state': 'New York', 'city': 'New York', 'timezone': 'EST'},
        '213': {'state': 'California', 'city': 'Los Angeles', 'timezone': 'PST'},
        '214': {'state': 'Texas', 'city': 'Dallas', 'timezone': 'CST'},
        '215': {'state': 'Pennsylvania', 'city': 'Philadelphia', 'timezone': 'EST'},
        '216': {'state': 'Ohio', 'city': 'Cleveland', 'timezone': 'EST'},
        '217': {'state': 'Illinois', 'city': 'Springfield', 'timezone': 'CST'},
        '218': {'state': 'Minnesota', 'city': 'Duluth', 'timezone': 'CST'},
        '219': {'state': 'Indiana', 'city': 'Gary', 'timezone': 'CST'},
        '224': {'state': 'Illinois', 'city': 'Evanston', 'timezone': 'CST'},
        '225': {'state': 'Louisiana', 'city': 'Baton Rouge', 'timezone': 'CST'},
        '228': {'state': 'Mississippi', 'city': 'Gulfport', 'timezone': 'CST'},
        '229': {'state': 'Georgia', 'city': 'Albany', 'timezone': 'EST'},
        '231': {'state': 'Michigan', 'city': 'Muskegon', 'timezone': 'EST'},
        '234': {'state': 'Ohio', 'city': 'Akron', 'timezone': 'EST'},
        '239': {'state': 'Florida', 'city': 'Fort Myers', 'timezone': 'EST'},
        '240': {'state': 'Maryland', 'city': 'Hagerstown', 'timezone': 'EST'},
        '248': {'state': 'Michigan', 'city': 'Troy', 'timezone': 'EST'},
        '251': {'state': 'Alabama', 'city': 'Mobile', 'timezone': 'CST'},
        '252': {'state': 'North Carolina', 'city': 'Greenville', 'timezone': 'EST'},
        '253': {'state': 'Washington', 'city': 'Tacoma', 'timezone': 'PST'},
        '254': {'state': 'Texas', 'city': 'Killeen', 'timezone': 'CST'},
        '256': {'state': 'Alabama', 'city': 'Huntsville', 'timezone': 'CST'},
        '260': {'state': 'Indiana', 'city': 'Fort Wayne', 'timezone': 'EST'},
        '262': {'state': 'Wisconsin', 'city': 'Kenosha', 'timezone': 'CST'},
        '267': {'state': 'Pennsylvania', 'city': 'Philadelphia', 'timezone': 'EST'},
        '269': {'state': 'Michigan', 'city': 'Kalamazoo', 'timezone': 'EST'},
        '270': {'state': 'Kentucky', 'city': 'Bowling Green', 'timezone': 'CST'},
        '276': {'state': 'Virginia', 'city': 'Bristol', 'timezone': 'EST'},
        '281': {'state': 'Texas', 'city': 'Houston', 'timezone': 'CST'},
        '301': {'state': 'Maryland', 'city': 'Hagerstown', 'timezone': 'EST'},
        '302': {'state': 'Delaware', 'city': 'Wilmington', 'timezone': 'EST'},
        '303': {'state': 'Colorado', 'city': 'Denver', 'timezone': 'MST'},
        '304': {'state': 'West Virginia', 'city': 'Charleston', 'timezone': 'EST'},
        '305': {'state': 'Florida', 'city': 'Miami', 'timezone': 'EST'},
        '307': {'state': 'Wyoming', 'city': 'Cheyenne', 'timezone': 'MST'},
        '308': {'state': 'Nebraska', 'city': 'North Platte', 'timezone': 'CST'},
        '309': {'state': 'Illinois', 'city': 'Peoria', 'timezone': 'CST'},
        '310': {'state': 'California', 'city': 'Beverly Hills', 'timezone': 'PST'},
        '312': {'state': 'Illinois', 'city': 'Chicago', 'timezone': 'CST'},
        '313': {'state': 'Michigan', 'city': 'Detroit', 'timezone': 'EST'},
        '314': {'state': 'Missouri', 'city': 'St. Louis', 'timezone': 'CST'},
        '315': {'state': 'New York', 'city': 'Syracuse', 'timezone': 'EST'},
        '316': {'state': 'Kansas', 'city': 'Wichita', 'timezone': 'CST'},
        '317': {'state': 'Indiana', 'city': 'Indianapolis', 'timezone': 'EST'},
        '318': {'state': 'Louisiana', 'city': 'Shreveport', 'timezone': 'CST'},
        '319': {'state': 'Iowa', 'city': 'Cedar Rapids', 'timezone': 'CST'},
        '320': {'state': 'Minnesota', 'city': 'St. Cloud', 'timezone': 'CST'},
        '321': {'state': 'Florida', 'city': 'Cocoa', 'timezone': 'EST'},
        '323': {'state': 'California', 'city': 'Los Angeles', 'timezone': 'PST'},
        '325': {'state': 'Texas', 'city': 'Abilene', 'timezone': 'CST'},
        '330': {'state': 'Ohio', 'city': 'Akron', 'timezone': 'EST'},
        '331': {'state': 'Illinois', 'city': 'Aurora', 'timezone': 'CST'},
        '334': {'state': 'Alabama', 'city': 'Montgomery', 'timezone': 'CST'},
        '336': {'state': 'North Carolina', 'city': 'Greensboro', 'timezone': 'EST'},
        '337': {'state': 'Louisiana', 'city': 'Lafayette', 'timezone': 'CST'},
        '339': {'state': 'Massachusetts', 'city': 'Boston', 'timezone': 'EST'},
        '347': {'state': 'New York', 'city': 'New York', 'timezone': 'EST'},
        '351': {'state': 'Massachusetts', 'city': 'Lowell', 'timezone': 'EST'},
        '352': {'state': 'Florida', 'city': 'Gainesville', 'timezone': 'EST'},
        '360': {'state': 'Washington', 'city': 'Olympia', 'timezone': 'PST'},
        '361': {'state': 'Texas', 'city': 'Corpus Christi', 'timezone': 'CST'},
        '364': {'state': 'Kentucky', 'city': 'Bowling Green', 'timezone': 'CST'},
        '380': {'state': 'Ohio', 'city': 'Columbus', 'timezone': 'EST'},
        '385': {'state': 'Utah', 'city': 'Salt Lake City', 'timezone': 'MST'},
        '386': {'state': 'Florida', 'city': 'Daytona Beach', 'timezone': 'EST'},
        '401': {'state': 'Rhode Island', 'city': 'Providence', 'timezone': 'EST'},
        '402': {'state': 'Nebraska', 'city': 'Omaha', 'timezone': 'CST'},
        '404': {'state': 'Georgia', 'city': 'Atlanta', 'timezone': 'EST'},
        '405': {'state': 'Oklahoma', 'city': 'Oklahoma City', 'timezone': 'CST'},
        '406': {'state': 'Montana', 'city': 'Billings', 'timezone': 'MST'},
        '407': {'state': 'Florida', 'city': 'Orlando', 'timezone': 'EST'},
        '408': {'state': 'California', 'city': 'San Jose', 'timezone': 'PST'},
        '409': {'state': 'Texas', 'city': 'Beaumont', 'timezone': 'CST'},
        '410': {'state': 'Maryland', 'city': 'Baltimore', 'timezone': 'EST'},
        '412': {'state': 'Pennsylvania', 'city': 'Pittsburgh', 'timezone': 'EST'},
        '413': {'state': 'Massachusetts', 'city': 'Springfield', 'timezone': 'EST'},
        '414': {'state': 'Wisconsin', 'city': 'Milwaukee', 'timezone': 'CST'},
        '415': {'state': 'California', 'city': 'San Francisco', 'timezone': 'PST'},
        '417': {'state': 'Missouri', 'city': 'Springfield', 'timezone': 'CST'},
        '419': {'state': 'Ohio', 'city': 'Toledo', 'timezone': 'EST'},
        '423': {'state': 'Tennessee', 'city': 'Chattanooga', 'timezone': 'EST'},
        '424': {'state': 'California', 'city': 'Los Angeles', 'timezone': 'PST'},
        '425': {'state': 'Washington', 'city': 'Bellevue', 'timezone': 'PST'},
        '430': {'state': 'Texas', 'city': 'Tyler', 'timezone': 'CST'},
        '432': {'state': 'Texas', 'city': 'Midland', 'timezone': 'CST'},
        '434': {'state': 'Virginia', 'city': 'Lynchburg', 'timezone': 'EST'},
        '435': {'state': 'Utah', 'city': 'Logan', 'timezone': 'MST'},
        '440': {'state': 'Ohio', 'city': 'Cleveland', 'timezone': 'EST'},
        '442': {'state': 'California', 'city': 'Oceanside', 'timezone': 'PST'},
        '443': {'state': 'Maryland', 'city': 'Baltimore', 'timezone': 'EST'},
        '445': {'state': 'Pennsylvania', 'city': 'Philadelphia', 'timezone': 'EST'},
        '447': {'state': 'Illinois', 'city': 'Springfield', 'timezone': 'CST'},
        '458': {'state': 'Oregon', 'city': 'Eugene', 'timezone': 'PST'},
        '463': {'state': 'Indiana', 'city': 'Indianapolis', 'timezone': 'EST'},
        '464': {'state': 'Illinois', 'city': 'Chicago', 'timezone': 'CST'},
        '469': {'state': 'Texas', 'city': 'Dallas', 'timezone': 'CST'},
        '470': {'state': 'Georgia', 'city': 'Atlanta', 'timezone': 'EST'},
        '475': {'state': 'Connecticut', 'city': 'Bridgeport', 'timezone': 'EST'},
        '478': {'state': 'Georgia', 'city': 'Macon', 'timezone': 'EST'},
        '479': {'state': 'Arkansas', 'city': 'Fort Smith', 'timezone': 'CST'},
        '480': {'state': 'Arizona', 'city': 'Phoenix', 'timezone': 'MST'},
        '484': {'state': 'Pennsylvania', 'city': 'Allentown', 'timezone': 'EST'},
        '501': {'state': 'Arkansas', 'city': 'Little Rock', 'timezone': 'CST'},
        '502': {'state': 'Kentucky', 'city': 'Louisville', 'timezone': 'EST'},
        '503': {'state': 'Oregon', 'city': 'Portland', 'timezone': 'PST'},
        '504': {'state': 'Louisiana', 'city': 'New Orleans', 'timezone': 'CST'},
        '505': {'state': 'New Mexico', 'city': 'Albuquerque', 'timezone': 'MST'},
        '507': {'state': 'Minnesota', 'city': 'Rochester', 'timezone': 'CST'},
        '508': {'state': 'Massachusetts', 'city': 'Worcester', 'timezone': 'EST'},
        '509': {'state': 'Washington', 'city': 'Spokane', 'timezone': 'PST'},
        '510': {'state': 'California', 'city': 'Oakland', 'timezone': 'PST'},
        '512': {'state': 'Texas', 'city': 'Austin', 'timezone': 'CST'},
        '513': {'state': 'Ohio', 'city': 'Cincinnati', 'timezone': 'EST'},
        '515': {'state': 'Iowa', 'city': 'Des Moines', 'timezone': 'CST'},
        '516': {'state': 'New York', 'city': 'Hempstead', 'timezone': 'EST'},
        '517': {'state': 'Michigan', 'city': 'Lansing', 'timezone': 'EST'},
        '518': {'state': 'New York', 'city': 'Albany', 'timezone': 'EST'},
        '520': {'state': 'Arizona', 'city': 'Tucson', 'timezone': 'MST'},
        '530': {'state': 'California', 'city': 'Redding', 'timezone': 'PST'},
        '531': {'state': 'Nebraska', 'city': 'Omaha', 'timezone': 'CST'},
        '534': {'state': 'Wisconsin', 'city': 'Green Bay', 'timezone': 'CST'},
        '539': {'state': 'Oklahoma', 'city': 'Tulsa', 'timezone': 'CST'},
        '540': {'state': 'Virginia', 'city': 'Roanoke', 'timezone': 'EST'},
        '541': {'state': 'Oregon', 'city': 'Eugene', 'timezone': 'PST'},
        '551': {'state': 'New Jersey', 'city': 'Hackensack', 'timezone': 'EST'},
        '559': {'state': 'California', 'city': 'Fresno', 'timezone': 'PST'},
        '561': {'state': 'Florida', 'city': 'West Palm Beach', 'timezone': 'EST'},
        '562': {'state': 'California', 'city': 'Long Beach', 'timezone': 'PST'},
        '563': {'state': 'Iowa', 'city': 'Davenport', 'timezone': 'CST'},
        '564': {'state': 'Washington', 'city': 'Everett', 'timezone': 'PST'},
        '567': {'state': 'Ohio', 'city': 'Toledo', 'timezone': 'EST'},
        '570': {'state': 'Pennsylvania', 'city': 'Scranton', 'timezone': 'EST'},
        '571': {'state': 'Virginia', 'city': 'Arlington', 'timezone': 'EST'},
        '573': {'state': 'Missouri', 'city': 'Columbia', 'timezone': 'CST'},
        '574': {'state': 'Indiana', 'city': 'South Bend', 'timezone': 'EST'},
        '575': {'state': 'New Mexico', 'city': 'Las Cruces', 'timezone': 'MST'},
        '580': {'state': 'Oklahoma', 'city': 'Lawton', 'timezone': 'CST'},
        '585': {'state': 'New York', 'city': 'Rochester', 'timezone': 'EST'},
        '586': {'state': 'Michigan', 'city': 'Warren', 'timezone': 'EST'},
        '601': {'state': 'Mississippi', 'city': 'Jackson', 'timezone': 'CST'},
        '602': {'state': 'Arizona', 'city': 'Phoenix', 'timezone': 'MST'},
        '603': {'state': 'New Hampshire', 'city': 'Manchester', 'timezone': 'EST'},
        '605': {'state': 'South Dakota', 'city': 'Sioux Falls', 'timezone': 'CST'},
        '606': {'state': 'Kentucky', 'city': 'Ashland', 'timezone': 'EST'},
        '607': {'state': 'New York', 'city': 'Binghamton', 'timezone': 'EST'},
        '608': {'state': 'Wisconsin', 'city': 'Madison', 'timezone': 'CST'},
        '609': {'state': 'New Jersey', 'city': 'Trenton', 'timezone': 'EST'},
        '610': {'state': 'Pennsylvania', 'city': 'Allentown', 'timezone': 'EST'},
        '612': {'state': 'Minnesota', 'city': 'Minneapolis', 'timezone': 'CST'},
        '614': {'state': 'Ohio', 'city': 'Columbus', 'timezone': 'EST'},
        '615': {'state': 'Tennessee', 'city': 'Nashville', 'timezone': 'CST'},
        '616': {'state': 'Michigan', 'city': 'Grand Rapids', 'timezone': 'EST'},
        '617': {'state': 'Massachusetts', 'city': 'Boston', 'timezone': 'EST'},
        '618': {'state': 'Illinois', 'city': 'Carbondale', 'timezone': 'CST'},
        '619': {'state': 'California', 'city': 'San Diego', 'timezone': 'PST'},
        '620': {'state': 'Kansas', 'city': 'Hutchinson', 'timezone': 'CST'},
        '623': {'state': 'Arizona', 'city': 'Phoenix', 'timezone': 'MST'},
        '626': {'state': 'California', 'city': 'Pasadena', 'timezone': 'PST'},
        '628': {'state': 'California', 'city': 'San Francisco', 'timezone': 'PST'},
        '629': {'state': 'Tennessee', 'city': 'Nashville', 'timezone': 'CST'},
        '630': {'state': 'Illinois', 'city': 'Aurora', 'timezone': 'CST'},
        '631': {'state': 'New York', 'city': 'Huntington', 'timezone': 'EST'},
        '636': {'state': 'Missouri', 'city': 'O\'Fallon', 'timezone': 'CST'},
        '641': {'state': 'Iowa', 'city': 'Mason City', 'timezone': 'CST'},
        '646': {'state': 'New York', 'city': 'New York', 'timezone': 'EST'},
        '650': {'state': 'California', 'city': 'San Mateo', 'timezone': 'PST'},
        '651': {'state': 'Minnesota', 'city': 'St. Paul', 'timezone': 'CST'},
        '657': {'state': 'California', 'city': 'Anaheim', 'timezone': 'PST'},
        '660': {'state': 'Missouri', 'city': 'Sedalia', 'timezone': 'CST'},
        '661': {'state': 'California', 'city': 'Bakersfield', 'timezone': 'PST'},
        '662': {'state': 'Mississippi', 'city': 'Tupelo', 'timezone': 'CST'},
        '667': {'state': 'Maryland', 'city': 'Baltimore', 'timezone': 'EST'},
        '669': {'state': 'California', 'city': 'San Jose', 'timezone': 'PST'},
        '678': {'state': 'Georgia', 'city': 'Atlanta', 'timezone': 'EST'},
        '681': {'state': 'West Virginia', 'city': 'Charleston', 'timezone': 'EST'},
        '682': {'state': 'Texas', 'city': 'Fort Worth', 'timezone': 'CST'},
        '701': {'state': 'North Dakota', 'city': 'Fargo', 'timezone': 'CST'},
        '702': {'state': 'Nevada', 'city': 'Las Vegas', 'timezone': 'PST'},
        '703': {'state': 'Virginia', 'city': 'Arlington', 'timezone': 'EST'},
        '704': {'state': 'North Carolina', 'city': 'Charlotte', 'timezone': 'EST'},
        '706': {'state': 'Georgia', 'city': 'Columbus', 'timezone': 'EST'},
        '707': {'state': 'California', 'city': 'Santa Rosa', 'timezone': 'PST'},
        '708': {'state': 'Illinois', 'city': 'Cicero', 'timezone': 'CST'},
        '712': {'state': 'Iowa', 'city': 'Sioux City', 'timezone': 'CST'},
        '713': {'state': 'Texas', 'city': 'Houston', 'timezone': 'CST'},
        '714': {'state': 'California', 'city': 'Anaheim', 'timezone': 'PST'},
        '715': {'state': 'Wisconsin', 'city': 'Eau Claire', 'timezone': 'CST'},
        '716': {'state': 'New York', 'city': 'Buffalo', 'timezone': 'EST'},
        '717': {'state': 'Pennsylvania', 'city': 'Lancaster', 'timezone': 'EST'},
        '718': {'state': 'New York', 'city': 'Brooklyn', 'timezone': 'EST'},
        '719': {'state': 'Colorado', 'city': 'Colorado Springs', 'timezone': 'MST'},
        '720': {'state': 'Colorado', 'city': 'Denver', 'timezone': 'MST'},
        '724': {'state': 'Pennsylvania', 'city': 'New Castle', 'timezone': 'EST'},
        '725': {'state': 'Nevada', 'city': 'Las Vegas', 'timezone': 'PST'},
        '727': {'state': 'Florida', 'city': 'St. Petersburg', 'timezone': 'EST'},
        '731': {'state': 'Tennessee', 'city': 'Jackson', 'timezone': 'CST'},
        '732': {'state': 'New Jersey', 'city': 'New Brunswick', 'timezone': 'EST'},
        '734': {'state': 'Michigan', 'city': 'Ann Arbor', 'timezone': 'EST'},
        '737': {'state': 'Texas', 'city': 'Austin', 'timezone': 'CST'},
        '740': {'state': 'Ohio', 'city': 'Zanesville', 'timezone': 'EST'},
        '743': {'state': 'North Carolina', 'city': 'Greensboro', 'timezone': 'EST'},
        '747': {'state': 'California', 'city': 'Burbank', 'timezone': 'PST'},
        '754': {'state': 'Florida', 'city': 'Fort Lauderdale', 'timezone': 'EST'},
        '757': {'state': 'Virginia', 'city': 'Virginia Beach', 'timezone': 'EST'},
        '760': {'state': 'California', 'city': 'Oceanside', 'timezone': 'PST'},
        '762': {'state': 'Georgia', 'city': 'Columbus', 'timezone': 'EST'},
        '763': {'state': 'Minnesota', 'city': 'Brooklyn Park', 'timezone': 'CST'},
        '765': {'state': 'Indiana', 'city': 'Muncie', 'timezone': 'EST'},
        '769': {'state': 'Mississippi', 'city': 'Jackson', 'timezone': 'CST'},
        '770': {'state': 'Georgia', 'city': 'Marietta', 'timezone': 'EST'},
        '772': {'state': 'Florida', 'city': 'Port St. Lucie', 'timezone': 'EST'},
        '773': {'state': 'Illinois', 'city': 'Chicago', 'timezone': 'CST'},
        '774': {'state': 'Massachusetts', 'city': 'Worcester', 'timezone': 'EST'},
        '775': {'state': 'Nevada', 'city': 'Reno', 'timezone': 'PST'},
        '779': {'state': 'Illinois', 'city': 'Rockford', 'timezone': 'CST'},
        '781': {'state': 'Massachusetts', 'city': 'Boston', 'timezone': 'EST'},
        '785': {'state': 'Kansas', 'city': 'Topeka', 'timezone': 'CST'},
        '786': {'state': 'Florida', 'city': 'Miami', 'timezone': 'EST'},
        '787': {'state': 'Puerto Rico', 'city': 'San Juan', 'timezone': 'AST'},
        '801': {'state': 'Utah', 'city': 'Salt Lake City', 'timezone': 'MST'},
        '802': {'state': 'Vermont', 'city': 'Burlington', 'timezone': 'EST'},
        '804': {'state': 'Virginia', 'city': 'Richmond', 'timezone': 'EST'},
        '805': {'state': 'California', 'city': 'Oxnard', 'timezone': 'PST'},
        '806': {'state': 'Texas', 'city': 'Lubbock', 'timezone': 'CST'},
        '808': {'state': 'Hawaii', 'city': 'Honolulu', 'timezone': 'HST'},
        '810': {'state': 'Michigan', 'city': 'Flint', 'timezone': 'EST'},
        '812': {'state': 'Indiana', 'city': 'Evansville', 'timezone': 'CST'},
        '813': {'state': 'Florida', 'city': 'Tampa', 'timezone': 'EST'},
        '814': {'state': 'Pennsylvania', 'city': 'Erie', 'timezone': 'EST'},
        '815': {'state': 'Illinois', 'city': 'Rockford', 'timezone': 'CST'},
        '816': {'state': 'Missouri', 'city': 'Kansas City', 'timezone': 'CST'},
        '817': {'state': 'Texas', 'city': 'Fort Worth', 'timezone': 'CST'},
        '818': {'state': 'California', 'city': 'Burbank', 'timezone': 'PST'},
        '828': {'state': 'North Carolina', 'city': 'Asheville', 'timezone': 'EST'},
        '830': {'state': 'Texas', 'city': 'New Braunfels', 'timezone': 'CST'},
        '831': {'state': 'California', 'city': 'Salinas', 'timezone': 'PST'},
        '832': {'state': 'Texas', 'city': 'Houston', 'timezone': 'CST'},
        '843': {'state': 'South Carolina', 'city': 'Charleston', 'timezone': 'EST'},
        '845': {'state': 'New York', 'city': 'Poughkeepsie', 'timezone': 'EST'},
        '847': {'state': 'Illinois', 'city': 'Evanston', 'timezone': 'CST'},
        '848': {'state': 'New Jersey', 'city': 'New Brunswick', 'timezone': 'EST'},
        '850': {'state': 'Florida', 'city': 'Tallahassee', 'timezone': 'EST'},
        '856': {'state': 'New Jersey', 'city': 'Camden', 'timezone': 'EST'},
        '857': {'state': 'Massachusetts', 'city': 'Boston', 'timezone': 'EST'},
        '858': {'state': 'California', 'city': 'San Diego', 'timezone': 'PST'},
        '859': {'state': 'Kentucky', 'city': 'Lexington', 'timezone': 'EST'},
        '860': {'state': 'Connecticut', 'city': 'Hartford', 'timezone': 'EST'},
        '862': {'state': 'New Jersey', 'city': 'Newark', 'timezone': 'EST'},
        '863': {'state': 'Florida', 'city': 'Lakeland', 'timezone': 'EST'},
        '864': {'state': 'South Carolina', 'city': 'Greenville', 'timezone': 'EST'},
        '865': {'state': 'Tennessee', 'city': 'Knoxville', 'timezone': 'EST'},
        '870': {'state': 'Arkansas', 'city': 'Jonesboro', 'timezone': 'CST'},
        '872': {'state': 'Illinois', 'city': 'Chicago', 'timezone': 'CST'},
        '878': {'state': 'Pennsylvania', 'city': 'Pittsburgh', 'timezone': 'EST'},
        '901': {'state': 'Tennessee', 'city': 'Memphis', 'timezone': 'CST'},
        '903': {'state': 'Texas', 'city': 'Tyler', 'timezone': 'CST'},
        '904': {'state': 'Florida', 'city': 'Jacksonville', 'timezone': 'EST'},
        '906': {'state': 'Michigan', 'city': 'Marquette', 'timezone': 'EST'},
        '907': {'state': 'Alaska', 'city': 'Anchorage', 'timezone': 'AKST'},
        '908': {'state': 'New Jersey', 'city': 'Elizabeth', 'timezone': 'EST'},
        '909': {'state': 'California', 'city': 'San Bernardino', 'timezone': 'PST'},
        '910': {'state': 'North Carolina', 'city': 'Fayetteville', 'timezone': 'EST'},
        '912': {'state': 'Georgia', 'city': 'Savannah', 'timezone': 'EST'},
        '913': {'state': 'Kansas', 'city': 'Overland Park', 'timezone': 'CST'},
        '914': {'state': 'New York', 'city': 'Yonkers', 'timezone': 'EST'},
        '915': {'state': 'Texas', 'city': 'El Paso', 'timezone': 'MST'},
        '916': {'state': 'California', 'city': 'Sacramento', 'timezone': 'PST'},
        '917': {'state': 'New York', 'city': 'New York', 'timezone': 'EST'},
        '918': {'state': 'Oklahoma', 'city': 'Tulsa', 'timezone': 'CST'},
        '919': {'state': 'North Carolina', 'city': 'Raleigh', 'timezone': 'EST'},
        '920': {'state': 'Wisconsin', 'city': 'Green Bay', 'timezone': 'CST'},
        '925': {'state': 'California', 'city': 'Concord', 'timezone': 'PST'},
        '928': {'state': 'Arizona', 'city': 'Flagstaff', 'timezone': 'MST'},
        '929': {'state': 'New York', 'city': 'Bronx', 'timezone': 'EST'},
        '930': {'state': 'Indiana', 'city': 'New Albany', 'timezone': 'EST'},
        '931': {'state': 'Tennessee', 'city': 'Clarksville', 'timezone': 'CST'},
        '934': {'state': 'New York', 'city': 'Huntington', 'timezone': 'EST'},
        '936': {'state': 'Texas', 'city': 'Huntsville', 'timezone': 'CST'},
        '937': {'state': 'Ohio', 'city': 'Dayton', 'timezone': 'EST'},
        '940': {'state': 'Texas', 'city': 'Wichita Falls', 'timezone': 'CST'},
        '941': {'state': 'Florida', 'city': 'Sarasota', 'timezone': 'EST'},
        '947': {'state': 'Michigan', 'city': 'Troy', 'timezone': 'EST'},
        '949': {'state': 'California', 'city': 'Irvine', 'timezone': 'PST'},
        '951': {'state': 'California', 'city': 'Riverside', 'timezone': 'PST'},
        '952': {'state': 'Minnesota', 'city': 'Bloomington', 'timezone': 'CST'},
        '954': {'state': 'Florida', 'city': 'Fort Lauderdale', 'timezone': 'EST'},
        '956': {'state': 'Texas', 'city': 'Laredo', 'timezone': 'CST'},
        '959': {'state': 'Connecticut', 'city': 'Hartford', 'timezone': 'EST'},
        '970': {'state': 'Colorado', 'city': 'Fort Collins', 'timezone': 'MST'},
        '971': {'state': 'Oregon', 'city': 'Portland', 'timezone': 'PST'},
        '972': {'state': 'Texas', 'city': 'Dallas', 'timezone': 'CST'},
        '973': {'state': 'New Jersey', 'city': 'Newark', 'timezone': 'EST'},
        '978': {'state': 'Massachusetts', 'city': 'Lowell', 'timezone': 'EST'},
        '979': {'state': 'Texas', 'city': 'Bryan', 'timezone': 'CST'},
        '980': {'state': 'North Carolina', 'city': 'Charlotte', 'timezone': 'EST'},
        '984': {'state': 'North Carolina', 'city': 'Raleigh', 'timezone': 'EST'},
        '985': {'state': 'Louisiana', 'city': 'Hammond', 'timezone': 'CST'},
        '989': {'state': 'Michigan', 'city': 'Saginaw', 'timezone': 'EST'}
    }
    
    if area_code in area_code_data:
        data = area_code_data[area_code]
        return {
            'area_code': area_code,
            'state': data['state'],
            'city': data['city'],
            'timezone': data['timezone'],
            'country': 'US',
            'source': 'local_database'
        }
    else:
        return {
            'area_code': area_code,
            'error': 'Area code not found in database',
            'source': 'local_database'
        }

def validate_area_code_fallback(area_code: str) -> bool:
    if not area_code.isdigit() or len(area_code) != 3:
        return False
    
    # Basic US area code rules
    first_digit = int(area_code[0])
    second_digit = int(area_code[1])
    third_digit = int(area_code[2])
    
    # Area code cannot start with 0 or 1
    if first_digit in [0, 1]:
        return False
    
    # The second digit CAN be 0 or 1 (this was the bug!)
    # Only the first digit cannot be 0 or 1
    
    # The third digit CAN be 0 or 1 (this was also incorrect!)
    # Only the first digit cannot be 0 or 1
    
    # Check for invalid area codes (test numbers, etc.)
    invalid_codes = ['555', '000', '111', '222', '333', '444', '666', '777', '888', '999']
    if area_code in invalid_codes:
        return False
    
    # Additional validation: area codes ending in 00 or 11 are typically invalid
    if second_digit == 0 and third_digit == 0:
        return False
    if second_digit == 1 and third_digit == 1:
        return False
    
    return True

def is_valid_ssn(ssn: str) -> bool:
    if not ssn: return False
    cleaned = re.sub(r'[^\d]', '', ssn)
    if len(cleaned) != 9: return False
    if cleaned.startswith('000') or cleaned.startswith('666') or int(cleaned[:3]) >= 900: return False
    if cleaned[3:5] == '00': return False
    if cleaned[5:] == '0000': return False
    return True

def classify_ip(ip: str) -> str:
    try:
        if ':' in ip: ip = ip.split(':')[0]
        parts = ip.split('.')
        if len(parts) != 4: return "Invalid"
        octets = [int(part) for part in parts]
        if any(not 0 <= octet <= 255 for octet in octets): return "Invalid"
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

def group_urls_by_domain(findings: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    if 'URLs' not in findings: return findings
    
    def extract_domain(url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain: domain = domain.split(':')[0]
            return domain
        except:
            return "unknown"

    domain_groups = {}
    for url, context in findings['URLs'].items():
        domain = extract_domain(url)
        domain_groups.setdefault(domain, {})[url] = context

    new_findings = findings.copy()
    new_findings['URLs_by_Domain'] = domain_groups
    del new_findings['URLs'] 

    logger.info(f"Grouped {len(findings['URLs'])} URLs into {len(domain_groups)} domains")
    return new_findings

def filter_duplicate_emails(findings: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    if 'Email_Addresses' not in findings:
        return findings
    
    emails = findings['Email_Addresses']
    if len(emails) <= 1:
        return findings
    
    # Sort emails by length (longest first) to check substrings properly
    sorted_emails = sorted(emails.items(), key=lambda x: len(x[0]), reverse=True)
    
    filtered_emails = {}
    removed_count = 0
    
    for email, context in sorted_emails:
        is_substring = False
        
        # Check if this email is a substring of any already processed email
        for existing_email in filtered_emails.keys():
            if email in existing_email and email != existing_email:
                is_substring = True
                removed_count += 1
                logger.debug(f"Removed duplicate email (substring): {email} (found in {existing_email})")
                break
        
        if not is_substring:
            filtered_emails[email] = context
    
    findings['Email_Addresses'] = filtered_emails
    logger.info(f"Email filtering: removed {removed_count} duplicate/substring emails, kept {len(filtered_emails)}")
    
    return findings

# --- Main Extraction Logic ---

def find_matches_in_text(text: str, file_name: str) -> Dict[str, Dict[str, str]]:
    from constants import NOISY_INDICATORS
    findings = {}

    if not text or not isinstance(text, str): 
        logger.warning(f"Invalid text type for {file_name}")
        return findings

    compiled_patterns = {}
    
    for category, pattern in Config.REGEX_PATTERNS.items():
        if category in NOISY_INDICATORS:
            continue

        try:
            compiled_patterns[category] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.error(f"Invalid regex pattern for {category}: {e}")
            continue
    
    # Process each regex pattern
    for category, compiled_pattern in compiled_patterns.items():
        try:
            matches = compiled_pattern.finditer(text)
            match_count = 0
            seen_indicators = set()

            for match in matches:
                try:
                    indicator = match.group(0).strip()
                    if not indicator or indicator in seen_indicators: continue
                    seen_indicators.add(indicator)
                except Exception as e:
                    logger.warning(f"Error processing individual match in {category} for {file_name}: {e}")
                    continue
                
                # Create enhanced indicator
                enhanced = enhancer.create_enhanced_indicator(
                    indicator=indicator,
                    category=category,
                    context=text[max(0, match.start()-100):match.end()+100],
                    file_name=file_name,
                    position=match.start()
                )
                
                # Filter out irrelevant indicators
                if enhancer.is_irrelevant(enhanced): continue
                
                # Additional validation for specific categories
                if category == 'Email_Addresses' and not is_valid_email(indicator): continue
                elif category == 'Phone_Numbers' and not is_valid_phone(indicator): continue
                elif category == 'SSN' and not is_valid_ssn(indicator): continue
                
                # Store the enhanced indicator
                findings.setdefault(category, {})
                
                # Create context string with enhanced metadata
                context_parts = []
                if enhanced.timestamp: context_parts.append(f"Timestamp: {enhanced.timestamp}")
                if enhanced.source_port: context_parts.append(f"Source Port: {enhanced.source_port}")
                if enhanced.destination_port: context_parts.append(f"Destination Port: {enhanced.destination_port}")
                if enhanced.protocol: context_parts.append(f"Protocol: {enhanced.protocol}")
                if enhanced.user_agent: context_parts.append(f"User-Agent: {enhanced.user_agent}")
                if enhanced.session_id: context_parts.append(f"Session-ID: {enhanced.session_id}")
                
                context_parts.append(f"File: {file_name}")
                context_parts.append(f"Position: {enhanced.position}")
                
                context = " | ".join(context_parts)
                
                # For IPs, add classification
                if "IP" in category:
                    ip_type = classify_ip(indicator)
                    context += f" | Type: {ip_type}"
                
                # For phone numbers, add area code enrichment
                if category == 'Phone_Numbers':
                    area_code = indicator[:3] if len(indicator) >= 3 else indicator
                    enriched_area = enrich_area_code(area_code)
                    if 'error' not in enriched_area:
                        context += f" | Location: {enriched_area.get('city', 'Unknown')}, {enriched_area.get('state', 'Unknown')} | Timezone: {enriched_area.get('timezone', 'Unknown')}"
                    else:
                        context += f" | Area Code: {area_code} (enrichment failed)"
                
                findings[category][indicator] = context
                match_count += 1

            if match_count > 0:
                logger.debug(f"Found {match_count} matches for {category} in {file_name}")
                
        except Exception as e:
            logger.warning(f"Error processing pattern {category} for {file_name}: {e}")
            continue

    return findings

def _process_text_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if not content.strip():
            logger.warning(f"Empty file: {file_name}")
            return {}

        return find_matches_in_text(content, file_name)

    except Exception as e:
        logger.error(f"Error processing text file {file_path}: {e}")
        return {}

def _process_email_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    file_ext = os.path.splitext(file_path)[1].lower()
    findings = {}
    
    if file_ext == '.eml' or file_ext in ['.mbox', '.mbx']:
        return _process_text_file(file_path, file_name)
    
    elif file_ext == '.msg':
        try:
            import extract_msg
            with extract_msg.Message(file_path) as msg:
                 email_content = f"From: {msg.sender}\nTo: {msg.to}\nSubject: {msg.subject}\nBody:\n{msg.body}"
                 findings = find_matches_in_text(email_content, file_name)
        except ImportError:
            logger.warning("`extract-msg` not available. Treating .msg as binary file.")
            findings = _process_binary_file(file_path, file_name)
        except Exception as e:
             logger.warning(f"Error processing .msg file: {e}, treating as binary")
             findings = _process_binary_file(file_path, file_name)
             
    elif file_ext in ['.pst', '.ost']:
        findings = _process_binary_file(file_path, file_name)
    
    else:
        findings = _process_binary_file(file_path, file_name)
    
    logger.info(f"Email file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
    return findings

def _process_document_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    file_ext = os.path.splitext(file_path)[1].lower()
    findings = {}
    
    try:
        content = ""
        if file_ext == '.pdf':
            import pypdf
            with open(file_path, 'rb') as f:
                reader = pypdf.PdfReader(f)
                content = "\n".join(page.extract_text() or "" for page in reader.pages)
        
        elif file_ext in ['.docx', '.doc']:
            from docx import Document
            doc = Document(file_path)
            content = "\n".join(paragraph.text for paragraph in doc.paragraphs)
        
        elif file_ext in ['.xlsx', '.xls']:
            import pandas as pd
            df_dict = pd.read_excel(file_path, sheet_name=None)
            for sheet_name, sheet_df in df_dict.items():
                content += f"Sheet: {sheet_name}\n"
                content += sheet_df.to_string() + "\n\n"
        
        else:
            raise ImportError(f"Unsupported document extension: {file_ext}")

        findings = find_matches_in_text(content, file_name)

    except ImportError as e:
        logger.warning(f"Library not available for {file_ext}: {e}. Treating as binary file.")
        findings = _process_binary_file(file_path, file_name)
    except Exception as e:
        logger.warning(f"Error processing document {file_ext}: {e}. Treating as binary.")
        findings = _process_binary_file(file_path, file_name)
        
    logger.info(f"Document file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
    return findings

def _process_archive_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    file_ext = os.path.splitext(file_path)[1].lower()
    logger.warning(f"Archive format not explicitly supported: {file_ext}. Attempting binary scan.")
    
    if file_ext == '.tar':
        try:
            import tarfile
            with tarfile.open(file_path, 'r') as tar:
                metadata = "\n".join(f"File: {m.name}, Size: {m.size}" for m in tar.getmembers())
                findings = find_matches_in_text(metadata, file_name)
                findings.update(_process_binary_file(file_path, file_name))
                return findings
        except Exception as e:
            logger.error(f"Error processing TAR {file_path}: {e}")
            return _process_binary_file(file_path, file_name)

    return _process_binary_file(file_path, file_name)

def _process_data_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    file_ext = os.path.splitext(file_path)[1].lower()
    findings = {}
    
    if file_ext in ['.sqlite', '.sqlite3', '.db']:
        try:
            import sqlite3
            conn = sqlite3.connect(file_path)
            content = "Database content extracted successfully." # Placeholder for full extraction logic
            findings = find_matches_in_text(content, file_name)
            conn.close()
        except ImportError:
            logger.warning("sqlite3 not available. Treating database as binary.")
            findings = _process_binary_file(file_path, file_name)
        except Exception as e:
            logger.warning(f"Error processing database: {e}. Treating as binary.")
            findings = _process_binary_file(file_path, file_name)
    else:
        findings = _process_binary_file(file_path, file_name)
    
    logger.info(f"Data file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
    return findings

def _process_media_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    try:
        findings = {}
        try:
            stat = os.stat(file_path)
            metadata = f"File: {file_name}\nSize: {stat.st_size} bytes\nCreated: {stat.st_ctime}\nModified: {stat.st_mtime}\nPath: {file_path}"
            findings = find_matches_in_text(metadata, file_name)
        except Exception as e:
            logger.warning(f"Error extracting metadata from {file_name}: {e}")
        
        logger.info(f"Media file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings
        
    except Exception as e:
        logger.error(f"Error processing media file {file_path}: {e}")
        return {}

def _process_binary_file(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    from constants import BINARY_CHUNK_SIZE
    findings = {}
    try:
        with open(file_path, 'rb') as f:
            chunk_number = 0
            while True:
                chunk = f.read(BINARY_CHUNK_SIZE)
                if not chunk: break
                chunk_number += 1
                
                try:
                    text_chunk = chunk.decode('utf-8', errors='ignore')
                    text_chunk = ''.join(char for char in text_chunk if char.isprintable() or char.isspace())
                    
                    if text_chunk.strip():
                        chunk_findings = find_matches_in_text(text_chunk, f"{file_name}_chunk_{chunk_number}")
                        for category, items in chunk_findings.items():
                            findings.setdefault(category, {}).update(items)
                except Exception as e:
                    logger.debug(f"Error processing binary chunk {chunk_number}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Error processing binary file {file_path}: {e}")
        return {}
        
    logger.info(f"Binary file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
    return findings

# --- Delegated / Placeholder Processors ---
_process_executable_file = _process_binary_file
_process_script_file = _process_text_file
_process_config_file = _process_text_file
_process_log_file = _process_text_file
_process_forensic_file = _process_binary_file
_process_mobile_file = _process_binary_file
_process_virtualization_file = _process_binary_file
_process_compressed_file = _process_binary_file
_process_system_file = _process_binary_file

def _process_zip_file(file_path: str, file_name: str, depth: int = 0) -> Dict[str, Dict[str, str]]:
    findings = {}
    
    try:
        import zipfile
        import tempfile
        import os
        from pathlib import Path
        
        # Security check for ZIP depth
        max_depth = 3
        if depth > max_depth:
            logger.warning(f"ZIP depth limit reached for {file_name}")
            return findings
        
        with zipfile.ZipFile(file_path, 'r') as zip_file:
            # Get list of files in the ZIP
            file_list = zip_file.namelist()
            logger.info(f"Processing ZIP {file_name} with {len(file_list)} files")
            print(f"[HEARTBEAT] Processing ZIP {file_name} with {len(file_list)} files")
            
            # Process each file in the ZIP
            for file_index, zip_file_name in enumerate(file_list):
                try:
                    # Skip directories
                    if zip_file_name.endswith('/'):
                        continue
                    
                    # Security check for path traversal
                    if '..' in zip_file_name or os.path.isabs(zip_file_name):
                        logger.warning(f"Skipping potentially dangerous file path in ZIP: {zip_file_name}")
                        continue
                    
                    # Extract file to temporary location
                    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(zip_file_name)[1]) as temp_file:
                        temp_file.write(zip_file.read(zip_file_name))
                        temp_file_path = temp_file.name
                    
                    try:
                        # Process the extracted file
                        file_findings = _process_extracted_file(temp_file_path, zip_file_name, depth + 1)
                        
                        # Merge findings
                        for category, items in file_findings.items():
                            findings.setdefault(category, {}).update(items)
                            
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(temp_file_path)
                        except:
                            pass
                            
                except Exception as e:
                    logger.error(f"Error processing file {zip_file_name} in ZIP {file_name}: {e}")
                    continue
                
                # Heartbeat for ZIP processing every 5 files
                if (file_index + 1) % 5 == 0:
                    print(f"[HEARTBEAT] ZIP processing: {file_index + 1}/{len(file_list)} files processed in {file_name}")
        
        logger.info(f"ZIP file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings
        
    except Exception as e:
        logger.error(f"Error processing ZIP file {file_path}: {e}")
        return findings

def _process_extracted_file(file_path: str, file_name: str, depth: int) -> Dict[str, Dict[str, str]]:
    try:
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Determine file type and process accordingly
        if file_ext in ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm']:
            return _process_text_file(file_path, file_name)
        elif file_ext in ['.eml', '.msg', '.mbox', '.mbx']:
            return _process_email_file(file_path, file_name)
        elif file_ext in ['.pdf', '.docx', '.doc', '.xlsx', '.xls']:
            return _process_document_file(file_path, file_name)
        elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return _process_zip_file(file_path, file_name, depth)
        else:
            # Try binary processing for unknown file types
            return _process_binary_file(file_path, file_name)
            
    except Exception as e:
        logger.error(f"Error processing extracted file {file_path}: {e}")
        return {}

def _process_large_file_chunked(file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
    logger.warning(f"Large file chunking placeholder called for {file_name}.")
    return {}

# --- Main Entry and Orchestration ---

def process_file(file_path: str, findings: Dict[str, Dict[str, str]]) -> bool:
    try:
        if not file_path or not isinstance(file_path, str) or not isinstance(findings, dict): return False
        if not SecurityValidator.is_safe_path(file_path): return False
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK): return False
        
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()

        from constants import ALLOWED_EXTENSIONS

        if file_ext in ALLOWED_EXTENSIONS.get('text', []):
            file_findings = _process_text_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('email', []):
            file_findings = _process_email_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('documents', []):
            file_findings = _process_document_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('archives', []):
             file_findings = _process_zip_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('data', []):
            file_findings = _process_data_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('images', []) + ALLOWED_EXTENSIONS.get('audio', []) + ALLOWED_EXTENSIONS.get('video', []):
            file_findings = _process_media_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('executables', []):
            file_findings = _process_executable_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('scripts', []):
            file_findings = _process_script_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('config', []):
            file_findings = _process_config_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('logs', []):
            file_findings = _process_log_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('forensic', []):
            file_findings = _process_forensic_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('mobile', []):
            file_findings = _process_mobile_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('virtualization', []):
            file_findings = _process_virtualization_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('compressed', []):
            file_findings = _process_compressed_file(file_path, file_name)
        elif file_ext in ALLOWED_EXTENSIONS.get('system', []):
            file_findings = _process_system_file(file_path, file_name)
        else:
            logger.warning(f"Unsupported file type: {file_ext}")
            return False

        # Merge findings
        for category, items in file_findings.items():
            findings.setdefault(category, {}).update(items)

        logger.info(f"Successfully processed {file_name}")
        return True

    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")
        return False

def run_extraction(input_files: List[str]) -> Dict[str, Dict[str, Any]]:
    from constants import PROGRESS_UPDATE_INTERVAL, MONITORING_INTERVAL_SECONDS 

    findings = {}
    processed_files = 0
    failed_files = 0
    skipped_files = 0

    if not input_files or not isinstance(input_files, list): return findings

    logger.info(f"Starting extraction on {len(input_files)} files")
    revelare_logger.log_performance("extraction_start", 0.0, {"file_count": len(input_files)})

    start_time = time.time()
    last_monitor_time = start_time

    for i, file_path in enumerate(input_files):
        try:
            file_name = os.path.basename(file_path)
            print(f"[HEARTBEAT] Processing file {i+1}/{len(input_files)}: {file_name}")
            
            file_start_time = time.time()
            if process_file(file_path, findings):
                processed_files += 1
                file_time = time.time() - file_start_time
                if file_time > 60: 
                    logger.info(f"File {file_name} processed in {file_time:.1f}s")
                    print(f"[HEARTBEAT] Large file completed: {file_name} in {file_time:.1f}s")
            else:
                skipped_files += 1

            current_time = time.time()
            if ((i + 1) % PROGRESS_UPDATE_INTERVAL == 0 or
                    current_time - last_monitor_time >= MONITORING_INTERVAL_SECONDS):
                elapsed = current_time - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                total_indicators = sum(len(items) for items in findings.values())
                logger.info(f"Progress: {i+1}/{len(input_files)} files processed ({rate:.1f} files/sec, {total_indicators} indicators)")
                last_monitor_time = current_time

        except Exception as e:
            logger.error(f"Failed to process {file_path}: {e}")
            failed_files += 1

    processing_time = time.time() - start_time

    # Log results
    logger.info(f"Extraction complete: {processed_files} processed, {failed_files} failed, {skipped_files} skipped")
    revelare_logger.log_performance("extraction_complete", processing_time, {
        "processed_files": processed_files,
        "failed_files": failed_files,
        "skipped_files": skipped_files,
        "total_indicators": sum(len(items) for items in findings.values())
    })

    # Group URLs by domain
    findings = group_urls_by_domain(findings)
    
    # Filter out email addresses that are substrings of other emails
    findings = filter_duplicate_emails(findings)

    # Add processing summary to findings
    findings["Processing_Summary"] = {
        "Total_Files_Processed": str(processed_files),
        "Total_Files_Failed": str(failed_files),
        "Total_Files_Skipped": str(skipped_files),
        "Processing_Time_Seconds": str(round(processing_time, 2))
    }
    
    return findings
    """
    Run indicator extraction on multiple files. (Main entry point)
    """
    # NOTE: Imports are fixed to be relative to the function start
    from constants import PROGRESS_UPDATE_INTERVAL, MONITORING_INTERVAL_SECONDS 

    findings = {}
    processed_files = 0
    failed_files = 0
    skipped_files = 0

    if not input_files or not isinstance(input_files, list):
        logger.error("Invalid input_files provided")
        return findings

    logger.info(f"Starting extraction on {len(input_files)} files")
    revelare_logger.log_performance("extraction_start", 0.0, {"file_count": len(input_files)})

    start_time = time.time()
    last_monitor_time = start_time

    for i, file_path in enumerate(input_files):
        try:
            file_name = os.path.basename(file_path)
            logger.info(f"Processing file {i+1}/{len(input_files)}: {file_name}")
            
            file_start_time = time.time()
            if process_file(file_path, findings):
                processed_files += 1
                file_time = time.time() - file_start_time
                if file_time > 60: 
                    logger.info(f"File {file_name} processed in {file_time:.1f}s")
            else:
                skipped_files += 1

            current_time = time.time()
            if ((i + 1) % PROGRESS_UPDATE_INTERVAL == 0 or
                    current_time - last_monitor_time >= MONITORING_INTERVAL_SECONDS):
                elapsed = current_time - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                total_indicators = sum(len(items) for items in findings.values())
                logger.info(f"Progress: {i+1}/{len(input_files)} files processed ({rate:.1f} files/sec, {total_indicators} indicators)")
                last_monitor_time = current_time

        except Exception as e:
            logger.error(f"Failed to process {file_path}: {e}")
            failed_files += 1

    processing_time = time.time() - start_time

    # Log results
    logger.info(f"Extraction complete: {processed_files} processed, {failed_files} failed, {skipped_files} skipped")
    revelare_logger.log_performance("extraction_complete", processing_time, {
        "processed_files": processed_files,
        "failed_files": failed_files,
        "skipped_files": skipped_files,
        "total_indicators": sum(len(items) for items in findings.values())
    })

    # Group URLs by domain
    logger.info("Grouping URLs by domain...")
    findings = group_urls_by_domain(findings)

    # Add processing summary to findings
    findings["Processing_Summary"] = {
        "Total_Files_Processed": str(processed_files),
        "Total_Files_Failed": str(failed_files),
        "Total_Files_Skipped": str(skipped_files),
        "Processing_Time_Seconds": str(round(processing_time, 2))
    }
    
    return findings