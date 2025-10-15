import os
import time
import requests
import logging
from typing import Dict, Optional, List, Any

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import InputValidator

logger = get_logger(__name__)
api_logger = RevelareLogger.get_logger('api_client')
perf_logger = RevelareLogger.get_logger('performance')

class GeoIPService:
    def __init__(self):
        self.asn_db_path = getattr(Config, 'ASN_DB_PATH', "GeoLite2-ASN.mmdb")
        self.city_db_path = getattr(Config, 'CITY_DB_PATH', "GeoLite2-City.mmdb")
        
        self.api_url = "http://ip-api.com/json/"
        self.api_rate_limit = getattr(Config, 'IP_API_RATE_LIMIT', 0.5)
        self.api_timeout = getattr(Config, 'IP_API_TIMEOUT', 15)
        self.last_api_request_time = 0.0
        
        self.validator = InputValidator()
        self.asn_reader = None
        self.city_reader = None
        self._initialize_databases()
        
    def _initialize_databases(self):
        try:
            import maxminddb
            if os.path.exists(self.asn_db_path):
                self.asn_reader = maxminddb.open_database(self.asn_db_path)
                logger.info(f"ASN database initialized: {self.asn_db_path}")
            else:
                 logger.warning(f"ASN database not found: {self.asn_db_path}")
            
            if os.path.exists(self.city_db_path):
                self.city_reader = maxminddb.open_database(self.city_db_path)
                logger.info(f"City database initialized: {self.city_db_path}")
            else:
                logger.warning(f"City database not found: {self.city_db_path}")
        except ImportError:
            logger.error("`maxminddb` library not found. Install with: pip install maxminddb")
        except Exception as e:
            logger.error(f"Error initializing GeoLite2 databases: {e}")
            
    def close(self):
        try:
            if self.asn_reader:
                self.asn_reader.close()
            if self.city_reader:
                self.city_reader.close()
        except Exception as e:
            logger.error(f"Error closing MaxMind databases: {e}")
            
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def enrich_ips(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        enriched_ips = {}
        unique_ips = sorted(list(set(ip_addresses)))
        
        for ip_with_port in unique_ips:
            # Extract IP from IP:port format
            ip = ip_with_port.split(':')[0] if ':' in ip_with_port else ip_with_port
            
            if not self.validator.is_valid_ip(ip) or self._is_non_global_ip(ip):
                 enriched_ips[ip_with_port] = {'error': 'Invalid or non-global IP address'}
                 continue

            local_data = self._lookup_local(ip)
            if local_data:
                enriched_ips[ip_with_port] = local_data
            else:
                api_data = self._lookup_api(ip)
                if api_data:
                    enriched_ips[ip_with_port] = api_data
                else:
                    enriched_ips[ip_with_port] = {'error': 'No data available'}
        
        return enriched_ips

    def _is_non_global_ip(self, ip: str) -> bool:
        try:
            from ipaddress import ip_address
            addr = ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
        except ValueError:
            return True

    def _lookup_local(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.asn_reader and not self.city_reader:
            return None
        
        try:
            result = {'query': ip, 'source': 'GeoLite2'}
            
            if self.asn_reader:
                asn_data = self.asn_reader.get(ip)
                if asn_data:
                    as_num = asn_data.get('autonomous_system_number')
                    as_org = asn_data.get('autonomous_system_organization')
                    if as_num: result['as'] = f"AS{as_num}"
                    if as_org: result['organization'] = as_org
            
            if self.city_reader:
                city_data = self.city_reader.get(ip)
                if city_data:
                    country = city_data.get('country', {}).get('names', {}).get('en')
                    region = city_data.get('subdivisions', [{}])[0].get('names', {}).get('en')
                    city = city_data.get('city', {}).get('names', {}).get('en')
                    location = city_data.get('location', {})
                    
                    if country: result['country'] = country
                    if region: result['region'] = region
                    if city: result['city'] = city
                    if location:
                        result['lat'] = str(location.get('latitude'))
                        result['lon'] = str(location.get('longitude'))

            return result if result.get('country') or result.get('as') else None
            
        except Exception as e:
            logger.error(f"Error in local lookup for {ip}: {e}")
            return None

    def _lookup_api(self, ip: str) -> Optional[Dict[str, str]]:
        elapsed = time.time() - self.last_api_request_time
        if elapsed < self.api_rate_limit:
            time.sleep(self.api_rate_limit - elapsed)
            
        try:
            response = requests.get(f"{self.api_url}{ip}", timeout=self.api_timeout)
            self.last_api_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'), 'region': data.get('regionName'),
                        'city': data.get('city'), 'isp': data.get('isp'),
                        'organization': data.get('org'), 'as': data.get('as'),
                        'lat': str(data.get('lat')), 'lon': str(data.get('lon')),
                        'query': data.get('query'), 'source': 'ip-api.com'
                    }
                else:
                    logger.warning(f"API failed for {ip}: {data.get('message')}")
                    return None
            else:
                logger.error(f"API returned HTTP {response.status_code} for {ip}.")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error for {ip}: {e}")
            return None