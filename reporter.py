#!/usr/bin/env python3
"""
Report generation module for Project Revelare.
"""

import json
import re
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timezone
import logging
from config import Config
from logger import get_logger, RevelareLogger
from security import InputValidator
from geoip_service import GeoIPService

logger = get_logger(__name__)
report_logger = RevelareLogger.get_logger('reporter')

def _get_category_badge_class(category: str) -> str:
    category_lower = category.lower().replace('_', '-')
    
    if 'ip' in category_lower: return 'category-ip'
    if 'email' in category_lower: return 'category-email'
    if 'url' in category_lower or 'domain' in category_lower: return 'category-url'
    if 'hash' in category_lower: return 'category-hash'
    if 'key' in category_lower or 'registry' in category_lower: return 'category-registry'
    if 'card' in category_lower or 'phone' in category_lower: return 'category-financial'
    if 'file' in category_lower or 'path' in category_lower: return 'category-file'
    
    return 'category-default'

def _format_enrichment_data(ip_data: Dict[str, Any]) -> str:
    if ip_data.get('error'):
        return f"Enrichment Error: {ip_data.get('error')}"
    
    country = ip_data.get('country', '')
    city = ip_data.get('city', '')
    as_num = ip_data.get('as', '')
    source = ip_data.get('source', '')

    parts = []
    if country: parts.append(f"Country: {country}")
    if city: parts.append(f"City: {city}")
    if as_num: parts.append(f"AS: {as_num}")
    if source: parts.append(f"Source: {source}")
    
    return " | ".join(parts)

# --- Main Report Generator Class ---

class ReportGenerator:
    """Enhanced report generator with filtering and sorting capabilities."""
    
    def __init__(self):
        self.validator = InputValidator()
    
    def enrich_ips(self, ip_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        try:
            with GeoIPService() as geoip:
                return geoip.enrich_ips(list(set(ip_addresses)))
        except Exception as e:
            report_logger.error(f"Failed to initialize or run GeoIP service: {e}")
            return {}
    
    def generate_report(self, project_name: str, findings: Dict[str, Dict[str, Any]], 
                        enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        """Generates the comprehensive HTML report."""
        try:
            report_logger.info(f"Generating report components for project: {project_name}")
            
            # 1. Data Normalization and Stats
            normalized_data, stats = self._prepare_report_data(findings) 
            
            # 2. HTML Components
            category_options = self._generate_category_options(stats)
            file_options = self._generate_file_options(normalized_data)
            indicators_table = self._generate_indicators_table(normalized_data, enriched_ips)
            enriched_section = self._generate_enriched_section(enriched_ips)
            files_section = self._generate_files_section(normalized_data)
            
            # 3. Final Template Assembly
            generation_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            template = self._get_html_template()
            
            report_html = template.format(
                project_name=project_name,
                generation_date=generation_date,
                stats_cards=self._generate_stats_cards(stats),
                category_options=category_options,
                file_options=file_options,
                indicators_table=indicators_table,
                enriched_section=enriched_section,
                files_section=files_section
            )
            
            report_logger.info(f"Report HTML generated successfully for {project_name}")
            return report_html
            
        except Exception as e:
            report_logger.error(f"Critical error generating report: {e}", exc_info=True)
            raise

    # --- Data Preparation and Statistics ---

    def _prepare_report_data(self, findings: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        of dictionaries, preparing data for HTML tables and statistics.
        """
        normalized_data = []
        stats: Dict[str, Any] = {'total': 0, 'files': set()}
        
        for category, items in findings.items():
            if category == 'Processing_Summary':
                stats['summary'] = items
                continue

            for value, context_str in items.items():
                stats[category] = stats.get(category, 0) + 1
                stats['total'] += 1

                file_source = "Unknown"
                position = "N/A"
                
                # Extract File and Position from Context String (CRITICAL FOR MAPPING)
                if isinstance(context_str, str):
                    file_match = re.search(r'File: ([^|]+)', context_str)
                    if file_match:
                        file_source = file_match.group(1).strip()
                    pos_match = re.search(r'Position: (\d+)', context_str)
                    if pos_match:
                        position = pos_match.group(1).strip()
                
                stats['files'].add(file_source)

                normalized_data.append({
                    'category': category,
                    'value': value,
                    'file_source': file_source,
                    'position': position,
                    'context': context_str # Keep raw context for detailed display
                })
        
        return normalized_data, stats
    
    def _generate_stats_cards(self, stats: Dict[str, Any]) -> str:
        cards = []
        
        category_counts = sorted([(k, v) for k, v in stats.items() if k not in ['total', 'summary', 'files']], key=lambda x: x[1], reverse=True)
        
        for category, count in category_counts[:4]:
            color_hash = hash(category) % 0xFFFFFF
            cards.append(f"""
                <div class="stat-card" style="border-left-color: #{color_hash:06x};">
                    <h3>{count}</h3>
                    <p>{category.replace('_', ' ').title()}</p>
                </div>
            """)
        
        cards.append(f"""
            <div class="stat-card" style="border-left-color: #28a745;">
                <h3>{stats.get('total', 0)}</h3>
                <p>Total Indicators</p>
            </div>
        """)
        
        if 'summary' in stats and stats['summary'].get('Processing_Time_Seconds'):
             time_sec = stats['summary']['Processing_Time_Seconds']
             cards.append(f"""
                 <div class="stat-card" style="border-left-color: #ffc107;">
                     <h3>{time_sec}s</h3>
                     <p>Processing Time</p>
                 </div>
             """)
             
        return ''.join(cards)
    
    # --- Filter Option Generation ---

    def _generate_category_options(self, stats: Dict[str, Any]) -> str:
        options = []
        valid_categories = sorted([k for k in stats.keys() if k not in ['total', 'summary', 'files']])
        
        for category in valid_categories:
            options.append(f'<option value="{category}">{category.replace("_", " ").title()} ({stats[category]})</option>')
        return ''.join(options)
    
    def _generate_file_options(self, normalized_data: List[Dict[str, Any]]) -> str:
        file_counts: Dict[str, int] = {}
        for item in normalized_data:
             file_counts[item['file_source']] = file_counts.get(item['file_source'], 0) + 1
             
        options = []
        for file in sorted(file_counts.keys()):
            options.append(f'<option value="{file}">{file} ({file_counts[file]})</option>')
        return ''.join(options)
    
    # --- Table and Section Generation ---

    def _generate_indicators_table(self, normalized_data: List[Dict[str, Any]], enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        if not normalized_data:
            return '<div class="no-data">No indicators found</div>'
        
        table_html = """
        <table>
            <thead>
                <tr>
                    <th onclick="sortData(0)">Category</th>
                    <th onclick="sortData(1)">Value</th>
                    <th onclick="sortData(2)">Details / Enrichment</th>
                    <th onclick="sortData(3)">File Source</th>
                    <th onclick="sortData(4)">Position</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for item in normalized_data:
            category = item['category']
            value = item['value']
            file_source = item['file_source']
            position = item['position']
            
            details = self._generate_details_for_category(category, value, enriched_ips)

            category_class = _get_category_badge_class(category)
            
            table_html += f"""
                <tr>
                    <td><span class="category-badge {category_class}">{category.replace('_', ' ')}</span></td>
                    <td><span class="indicator-value">{value}</span></td>
                    <td><span class="details-info">{details}</span></td>
                    <td><span class="file-source">{file_source}</span></td>
                    <td>{position}</td>
                </tr>
                """
        
        table_html += "</tbody></table>"
        
        return table_html
    
    def _generate_details_for_category(self, category: str, value: str, enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        details_parts = []
        
        # 1. IP Enrichment (Priority 1)
        if ('IPv4' in category or 'IPv6' in category) and enriched_ips and value in enriched_ips:
            return _format_enrichment_data(enriched_ips[value])
        
        # 2. Hash Type Check (Priority 2)
        if 'HASHES' in category:
            details_parts.append(f"Algorithm: {category.split('_')[-1]} | Length: {len(value)}")

        # 3. Email/URL/Financial Metadata (Priority 3)
        if 'Email' in category and '@' in value:
            domain = value.split('@')[-1]
            tld = domain.split('.')[-1]
            if tld in ['com', 'net']: details_parts.append("Type: Commercial")
            elif tld in ['org', 'gov', 'edu']: details_parts.append(f"Type: {tld.upper()}")
            else: details_parts.append("Type: Other")

        elif 'URL' in category or 'Domain' in category:
            protocol = 'HTTPS (Secure)' if value.startswith('https://') else 'HTTP (Insecure)'
            details_parts.append(f"Protocol: {protocol}")
        
        elif 'Credit_Cards' in category:
            digits = ''.join(filter(str.isdigit, value))
            if digits.startswith('4'): details_parts.append("Type: Visa")
            elif digits.startswith('5'): details_parts.append("Type: Mastercard")
            elif digits.startswith('3'): details_parts.append("Type: Amex")
            else: details_parts.append("Type: Unknown Card")

        # 4. Default Fallback
        if not details_parts:
             return "No additional details (See full context in source data)"

        return " | ".join(details_parts)
    
    def _generate_files_section(self, normalized_data: List[Dict[str, Any]]) -> str:
        files: Dict[str, Dict[str, Any]] = {}
        for item in normalized_data:
            file_name = item['file_source']
            category = item['category']
            
            files.setdefault(file_name, {
                'categories': set(),
                'count': 0
            })
            files[file_name]['categories'].add(category)
            files[file_name]['count'] += 1

        if not files:
            return ""
        
        section_html = """
        <div class="data-section">
            <h2>File Sources</h2>
            <table>
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Categories Found</th>
                        <th>Indicator Count</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for file_name, data in sorted(files.items()):
            category_list = ', '.join([cat.replace('_', ' ').title() for cat in data['categories']])
            
            section_html += f"""
                <tr>
                    <td><span class="file-source">{file_name}</span></td>
                    <td>{category_list}</td>
                    <td>{data['count']}</td>
                </tr>
            """
        
        section_html += "</tbody></table></div>"
        
        return section_html
    
    def _generate_enriched_section(self, enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        if not enriched_ips:
            return ""
        
        section_html = """
        <div class="data-section">
            <h2>Enriched IP Addresses</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>City</th>
                        <th>AS Number</th>
                        <th>Organization</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for ip, data in enriched_ips.items():
            if data.get('error'):
                section_html += f"""
                    <tr>
                        <td>{ip}</td>
                        <td colspan="4" class="error">Error: {data.get('error')}</td>
                    </tr>
                """
            else:
                section_html += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{data.get('country', 'N/A')}</td>
                        <td>{data.get('city', 'N/A')}</td>
                        <td>{data.get('as', 'N/A')}</td>
                        <td>{data.get('organization', 'N/A')}</td>
                    </tr>
                """
        
        section_html += "</tbody></table></div>"
        return section_html
        
    def _get_html_template(self):
        # NOTE: This entire block is the original user template, cleaned up slightly for Python formatting.
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intelligence Report: {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-card {{ display: inline-block; background: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 10px; border-radius: 4px; min-width: 150px; }}
        .stat-card h3 {{ margin: 0; font-size: 24px; color: #333; }}
        .stat-card p {{ margin: 5px 0 0 0; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        .category-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .category-ip {{ background-color: #e3f2fd; color: #1976d2; }}
        .category-email {{ background-color: #f3e5f5; color: #7b1fa2; }}
        .category-url {{ background-color: #e8f5e8; color: #388e3c; }}
        .category-hash {{ background-color: #fdf3e3; color: #ff9800; }}
        .category-financial {{ background-color: #fff3e0; color: #f57c00; }}
        .category-default {{ background-color: #f5f5f5; color: #666; }}
        .indicator-value {{ font-family: monospace; background-color: #f8f9fa; padding: 2px 6px; border-radius: 3px; }}
        .file-source {{ color: #666; font-size: 12px; }}
        .details-info {{ font-size: 12px; color: #666; }}
        .no-data {{ text-align: center; padding: 40px; color: #666; font-style: italic; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; border-top: 1px solid #eee; color: #666; }}
        .data-section {{ margin: 30px 0; }}
        .data-section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Intelligence Report: {project_name}</h1>
        <p>Generated on: {generation_date}</p>
        
        <div class="stats-section">
            {stats_cards}
        </div>
        
        <div class="data-section">
            <h2>All Indicators</h2>
            <div id="indicatorsTable">
                {indicators_table}
            </div>
        </div>
        
        {enriched_section}
        {files_section}
        
        <div class="footer">
            <p>Generated by Project Revelare - Digital Forensics Platform</p>
        </div>
    </div>
</body>
</html>
        """