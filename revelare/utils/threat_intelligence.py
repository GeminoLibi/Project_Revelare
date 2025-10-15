"""
Threat Intelligence Service
Implements actual API calls to external threat intelligence services
"""

import requests
import time
import logging
from typing import Dict, List, Any, Optional
from revelare.config.config import Config

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    """Service for querying external threat intelligence APIs"""
    
    def __init__(self):
        self.last_request_times = {}
        self.rate_limits = {
            'abuseipdb': Config.ABUSEIPDB_RATE_LIMIT,
            'virustotal': Config.VIRUSTOTAL_RATE_LIMIT,
            'shodan': Config.SHODAN_RATE_LIMIT,
            'urlscan': Config.URLSCAN_RATE_LIMIT,
            'bitcoin_abuse': Config.BITCOIN_ABUSE_RATE_LIMIT,
            'chainabuse': Config.CHAINABUSE_RATE_LIMIT
        }
        self.timeouts = {
            'abuseipdb': Config.ABUSEIPDB_TIMEOUT,
            'virustotal': Config.VIRUSTOTAL_TIMEOUT,
            'shodan': Config.SHODAN_TIMEOUT,
            'urlscan': Config.URLSCAN_TIMEOUT,
            'bitcoin_abuse': Config.BITCOIN_ABUSE_TIMEOUT,
            'chainabuse': Config.CHAINABUSE_TIMEOUT
        }
    
    def _rate_limit(self, service: str):
        """Apply rate limiting for the specified service"""
        if service in self.last_request_times:
            elapsed = time.time() - self.last_request_times[service]
            if elapsed < self.rate_limits[service]:
                time.sleep(self.rate_limits[service] - elapsed)
        self.last_request_times[service] = time.time()
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB"""
        if not Config.ABUSEIPDB_API_KEY:
            return {'error': 'AbuseIPDB API key not configured'}
        
        self._rate_limit('abuseipdb')
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': Config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, 
                                  timeout=self.timeouts['abuseipdb'])
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    ip_data = data['data']
                    return {
                        'abuse_confidence': ip_data.get('abuseConfidencePercentage', 0),
                        'country': ip_data.get('countryCode', ''),
                        'usage_type': ip_data.get('usageType', ''),
                        'isp': ip_data.get('isp', ''),
                        'domain': ip_data.get('domain', ''),
                        'total_reports': ip_data.get('totalReports', 0),
                        'last_reported': ip_data.get('lastReportedAt', ''),
                        'is_public': ip_data.get('isPublic', False),
                        'is_whitelisted': ip_data.get('isWhitelisted', False),
                        'source': 'abuseipdb'
                    }
                else:
                    return {'error': 'No data returned from AbuseIPDB'}
            else:
                logger.warning(f"AbuseIPDB API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using VirusTotal"""
        if not Config.VIRUSTOTAL_API_KEY:
            return {'error': 'VirusTotal API key not configured'}
        
        self._rate_limit('virustotal')
        
        try:
            # First, get URL report
            url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {
                'apikey': Config.VIRUSTOTAL_API_KEY,
                'resource': url
            }
            
            response = requests.get(url_report_url, params=params, 
                                  timeout=self.timeouts['virustotal'])
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:  # URL found
                    scans = data.get('scans', {})
                    positives = data.get('positives', 0)
                    total = data.get('total', 0)
                    
                    return {
                        'positives': positives,
                        'total_scans': total,
                        'scan_date': data.get('scan_date', ''),
                        'permalink': data.get('permalink', ''),
                        'detected_by': [engine for engine, result in scans.items() 
                                      if result.get('detected')],
                        'malicious': positives > 0,
                        'confidence': (positives / total * 100) if total > 0 else 0,
                        'source': 'virustotal'
                    }
                else:
                    return {'error': 'URL not found in VirusTotal database'}
            else:
                logger.warning(f"VirusTotal API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def check_ip_device_info(self, ip: str) -> Dict[str, Any]:
        """Check IP device information using Shodan"""
        if not Config.SHODAN_API_KEY:
            return {'error': 'Shodan API key not configured'}
        
        self._rate_limit('shodan')
        
        try:
            url = f'https://api.shodan.io/shodan/host/{ip}'
            params = {'key': Config.SHODAN_API_KEY}
            
            response = requests.get(url, params=params, 
                                  timeout=self.timeouts['shodan'])
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', ''),
                    'city': data.get('city', ''),
                    'organization': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'os': data.get('os', ''),
                    'ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', []),
                    'last_update': data.get('last_update', ''),
                    'hostnames': data.get('hostnames', []),
                    'tags': data.get('tags', []),
                    'source': 'shodan'
                }
            else:
                logger.warning(f"Shodan API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Shodan API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis using URLScan"""
        if not Config.URLSCAN_API_KEY:
            return {'error': 'URLScan API key not configured'}
        
        self._rate_limit('urlscan')
        
        try:
            # Submit URL for scanning
            submit_url = 'https://urlscan.io/api/v1/scan/'
            headers = {
                'API-Key': Config.URLSCAN_API_KEY,
                'Content-Type': 'application/json'
            }
            data = {
                'url': url,
                'visibility': 'public'
            }
            
            response = requests.post(submit_url, headers=headers, json=data,
                                   timeout=self.timeouts['urlscan'])
            
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('uuid')
                
                if scan_id:
                    return {
                        'scan_id': scan_id,
                        'result_url': f'https://urlscan.io/result/{scan_id}/',
                        'status': 'submitted',
                        'message': 'URL submitted for analysis. Results available in ~30 seconds.',
                        'source': 'urlscan'
                    }
                else:
                    return {'error': 'Failed to get scan ID from URLScan'}
            else:
                logger.warning(f"URLScan API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"URLScan API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def check_bitcoin_address(self, address: str) -> Dict[str, Any]:
        """Check Bitcoin address reputation using Bitcoin Abuse"""
        if not Config.BITCOIN_ABUSE_API_KEY:
            return {'error': 'Bitcoin Abuse API key not configured'}
        
        self._rate_limit('bitcoin_abuse')
        
        try:
            url = 'https://www.bitcoinabuse.com/api/reports/check'
            params = {
                'api_token': Config.BITCOIN_ABUSE_API_KEY,
                'address': address
            }
            
            response = requests.get(url, params=params, 
                                  timeout=self.timeouts['bitcoin_abuse'])
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_count': data.get('count', 0),
                    'first_seen': data.get('first_seen', ''),
                    'last_seen': data.get('last_seen', ''),
                    'address': data.get('address', address),
                    'is_abusive': data.get('count', 0) > 0,
                    'source': 'bitcoin_abuse'
                }
            else:
                logger.warning(f"Bitcoin Abuse API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Bitcoin Abuse API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def check_crypto_address(self, address: str) -> Dict[str, Any]:
        """Check cryptocurrency address using Chainabuse"""
        if not Config.CHAINABUSE_API_KEY:
            return {'error': 'Chainabuse API key not configured'}
        
        self._rate_limit('chainabuse')
        
        try:
            url = 'https://api.chainabuse.com/v1/addresses'
            headers = {
                'Authorization': f'Bearer {Config.CHAINABUSE_API_KEY}',
                'Content-Type': 'application/json'
            }
            params = {'address': address}
            
            response = requests.get(url, headers=headers, params=params,
                                  timeout=self.timeouts['chainabuse'])
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    address_data = data['data'][0] if data['data'] else {}
                    return {
                        'address': address_data.get('address', address),
                        'risk_score': address_data.get('risk_score', 0),
                        'risk_level': address_data.get('risk_level', 'unknown'),
                        'reports_count': address_data.get('reports_count', 0),
                        'first_seen': address_data.get('first_seen', ''),
                        'last_seen': address_data.get('last_seen', ''),
                        'is_abusive': address_data.get('reports_count', 0) > 0,
                        'source': 'chainabuse'
                    }
                else:
                    return {'error': 'Address not found in Chainabuse database'}
            else:
                logger.warning(f"Chainabuse API returned HTTP {response.status_code}")
                return {'error': f'API error: HTTP {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Chainabuse API request failed: {e}")
            return {'error': f'Request failed: {str(e)}'}
    
    def enrich_indicator(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Enrich a single indicator with all available threat intelligence"""
        results = {
            'indicator': indicator,
            'type': indicator_type,
            'enrichments': {}
        }
        
        if indicator_type == 'ip':
            # IP reputation check
            abuse_result = self.check_ip_reputation(indicator)
            if 'error' not in abuse_result:
                results['enrichments']['abuseipdb'] = abuse_result
            
            # Device information
            shodan_result = self.check_ip_device_info(indicator)
            if 'error' not in shodan_result:
                results['enrichments']['shodan'] = shodan_result
                
        elif indicator_type == 'url':
            # URL reputation check
            vt_result = self.check_url_reputation(indicator)
            if 'error' not in vt_result:
                results['enrichments']['virustotal'] = vt_result
            
            # URL analysis
            urlscan_result = self.scan_url(indicator)
            if 'error' not in urlscan_result:
                results['enrichments']['urlscan'] = urlscan_result
                
        elif indicator_type == 'bitcoin_address':
            # Bitcoin address check
            bitcoin_result = self.check_bitcoin_address(indicator)
            if 'error' not in bitcoin_result:
                results['enrichments']['bitcoin_abuse'] = bitcoin_result
                
        elif indicator_type == 'crypto_address':
            # General crypto address check
            crypto_result = self.check_crypto_address(indicator)
            if 'error' not in crypto_result:
                results['enrichments']['chainabuse'] = crypto_result
        
        return results
