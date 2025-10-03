#!/usr/bin/env python3
"""
GeoIP Service for Project Revelare - IP Address Enrichment.

Provides fast, high-confidence IP address geolocation and ASN lookup 
using local MaxMind GeoLite2 databases with a secure, rate-limited external 
API (ip-api.com) as a fallback mechanism.

Author: Project Revelare Team
Version: 1.1 (Tuned-Up)
License: MIT
"""

import os
import time
import requests
import logging
from typing import Dict, Optional, List, Any
from logger import get_logger, RevelareLogger
from security import InputValidator
from config import Config # Import Config for API rate limits

# Initialize logger for this module
logger = get_logger(__name__)
api_logger = RevelareLogger.get_logger('api_client')
perf_logger = RevelareLogger.get_logger('performance')

class GeoIPService:
    """GeoIP service with local MaxMind database and API fallback."""
    
    # --- Configuration and Initialization ---

    def __init__(self):
        # Database paths are now defined by the Config/Constants structure
        self.asn_db_path = Config.ASN_DB_PATH if hasattr(Config, 'ASN_DB_PATH') else "GeoLite2-ASN.mmdb"
        self.city_db_path = Config.CITY_DB_PATH if hasattr(Config, 'CITY_DB_PATH') else "GeoLite2-City.mmdb"
        
        # API Configuration
        self.api_url = "http://ip-api.com/json/"
        self.api_rate_limit = getattr(Config, 'IP_API_RATE_LIMIT', 0.5)
        self.api_timeout = getattr(Config, 'IP_API_TIMEOUT', 15)
        self.last_api_request_time = 0.0
        
        self.validator = InputValidator()
        self.asn_reader = None
        self.city_reader = None
        self._initialize_databases()
        
    def _initialize_databases(self):
        """Initialize MaxMind GeoLite2 database readers."""
        try:
            import maxminddb
            
            # Check for ASN DB
            if os.path.exists(self.asn_db_path):
                self.asn_reader = maxminddb.open_database(self.asn_db_path, maxminddb.MODE_MMAP) # Use MODE_MMAP instead of MODE_MMAP_EXT
                logger.info(f"ASN database initialized: {self.asn_db_path}")
            else:
                 logger.warning(f"ASN database not found: {self.asn_db_path}. Skipping ASN enrichment.")
            
            # Check for City DB
            if os.path.exists(self.city_db_path):
                self.city_reader = maxminddb.open_database(self.city_db_path, maxminddb.MODE_MMAP) # Use MODE_MMAP instead of MODE_MMAP_EXT
                logger.info(f"City database initialized: {self.city_db_path}")
            else:
                logger.warning(f"City database not found: {self.city_db_path}. Skipping Geolocation enrichment.")

        except ImportError:
            logger.error("`maxminddb` library not available. Install with: pip install maxminddb")
        except Exception as e:
            logger.error(f"Error initializing GeoLite2 databases: {e}")
            
    def close(self):
        """Close database readers."""
        try:
            if self.asn_reader:
                self.asn_reader.close()
            if self.city_reader:
                self.city_reader.close()
            logger.info("GeoIP databases closed successfully.")
        except Exception as e:
            logger.error(f"Error closing MaxMind databases: {e}")
            
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # --- Core Enrichment Logic ---

    def enrich_ips(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Enrich a list of IP addresses with geographical and network information.
        Prioritizes local lookup and uses API as fallback.
        """
        enriched_ips: Dict[str, Dict[str, Any]] = {}
        
        start_time = time.time()
        
        # 1. Filter and process unique IPs
        unique_ips = sorted(list(set(ip_addresses))) # Sort for consistent API access order
        
        for i, ip in enumerate(unique_ips, 1):
            # Pre-filter private/reserved IPs (optional, but good for reducing API calls)
            if not self.validator.is_valid_ip(ip) or self._is_non_global_ip(ip):
                 enriched_ips[ip] = {'error': 'Invalid or non-global IP address'}
                 logger.debug(f"Skipping non-global/invalid IP: {ip}")
                 continue

            # 2. Try local database first
            local_data = self._lookup_local(ip)
            if local_data:
                enriched_ips[ip] = local_data
            else:
                # 3. Fallback to API
                api_data = self._lookup_api(ip)
                if api_data:
                    enriched_ips[ip] = api_data
                else:
                    enriched_ips[ip] = {'error': 'No data available from local or API sources'}
                    logger.warning(f"No enrichment data found for IP: {ip}")

            # Performance monitoring (log status every 10 IPs or if API is used)
            if i % 10 == 0 or 'ip-api.com' in enriched_ips[ip].get('source', ''):
                 logger.debug(f"Enriched {i}/{len(unique_ips)} IPs. Current source for {ip}: {enriched_ips[ip].get('source', 'N/A')}")
        
        duration = time.time() - start_time
        # Use the RevelareLogger instance to log performance
        revelare_logger_instance = RevelareLogger()
        revelare_logger_instance.log_performance("geoip_enrichment", duration, {"count": len(unique_ips), "source": "Local+API"})
        
        return enriched_ips

    def _is_non_global_ip(self, ip: str) -> bool:
        """Helper to quickly check if an IP is private, reserved, or loopback."""
        try:
            from ipaddress import ip_address
            addr = ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
        except ValueError:
            return True # Treat invalid IPs as non-global for filtering

    # --- Local MaxMind Lookup ---

    def _lookup_local(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup IP in local GeoLite2 databases."""
        if not self.asn_reader and not self.city_reader:
            return None
        
        try:
            result = {
                'country': None, 'region': None, 'city': None, 
                'isp': None, 'org': None, 'as': None, 
                'lat': None, 'lon': None, 'timezone': None, 
                'query': ip, 'source': 'GeoLite2', 'raw_asn': None, 'raw_city': None
            }
            
            # 1. Get and process ASN data
            asn_data = self.asn_reader.get(ip) if self.asn_reader else None
            if asn_data:
                result['raw_asn'] = asn_data # Store raw data for debugging/legal trail
                autonomous_system_number = asn_data.get('autonomous_system_number')
                autonomous_system_organization = asn_data.get('autonomous_system_organization')
                
                if autonomous_system_number:
                    result['as'] = f"AS{autonomous_system_number}"
                if autonomous_system_organization:
                    result['org'] = autonomous_system_organization
                    result['isp'] = autonomous_system_organization # ISP often same as Org
            
            # 2. Get and process City data
            city_data = self.city_reader.get(ip) if self.city_reader else None
            if city_data:
                result['raw_city'] = city_data # Store raw data
                
                # Country
                country = city_data.get('country', {})
                result['country'] = country.get('names', {}).get('en')
                
                # Region/State (Subdivisions)
                subdivisions = city_data.get('subdivisions', [])
                if subdivisions:
                    result['region'] = subdivisions[0].get('names', {}).get('en')
                
                # City, Location, Timezone
                result['city'] = city_data.get('city', {}).get('names', {}).get('en')
                location = city_data.get('location', {})
                if location:
                    result['lat'] = str(location.get('latitude'))
                    result['lon'] = str(location.get('longitude'))
                    result['timezone'] = location.get('time_zone')
            
            # 3. Final Check: Return if any meaningful data was found
            if result.get('country') or result.get('as'):
                # Clean up None values before returning
                return {k: v for k, v in result.items() if v is not None}
            
            return None # No data found in local DBs
            
        except Exception as e:
            logger.error(f"Error in local lookup for {ip}: {e}")
            return None

    # --- External API Lookup ---

    def _lookup_api(self, ip: str) -> Optional[Dict[str, str]]:
        """Lookup IP using ip-api.com API as fallback, with rate limiting and logging."""
        
        # 1. Rate Limiting Check
        elapsed = time.time() - self.last_api_request_time
        if elapsed < self.api_rate_limit:
            wait_time = self.api_rate_limit - elapsed
            time.sleep(wait_time)
            
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.api_url}{ip}", timeout=self.api_timeout)
            
            self.last_api_request_time = time.time()
            duration = self.last_api_request_time - start_time
            
            # Use the RevelareLogger instance to log API requests
            revelare_logger_instance = RevelareLogger()
            revelare_logger_instance.log_api_request("ip-api.com", f"{self.api_url}{ip}", response.status_code, duration)

            if response.status_code == 200:
                data = response.json()
                
                # Check for API-specific failure (e.g., rate limit hit or invalid query)
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'lat': str(data.get('lat')),
                        'lon': str(data.get('lon')),
                        'timezone': data.get('timezone'),
                        'query': data.get('query'),
                        'source': 'ip-api.com'
                    }
                else:
                    logger.warning(f"API returned status failure for {ip}: {data.get('message', 'Unknown reason')}")
                    return None
            else:
                logger.error(f"API returned unexpected HTTP status {response.status_code} for {ip}.")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"API lookup timed out for {ip}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in API lookup for {ip}: {e}")
            return None