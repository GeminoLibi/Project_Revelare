import json
import re
from typing import Dict, List, Any
from datetime import datetime, timezone
import logging

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import InputValidator
from revelare.utils.geoip_service import GeoIPService

logger = get_logger(__name__)
report_logger = RevelareLogger.get_logger('reporter')

def _get_category_badge_class(category: str) -> str:
    category_lower = category.lower().replace('_', '-')
    if 'ip' in category_lower: return 'category-ip'
    if 'email' in category_lower: return 'category-email'
    if 'url' in category_lower: return 'category-url'
    if 'hash' in category_lower: return 'category-hash'
    if 'card' in category_lower or 'phone' in category_lower: return 'category-financial'
    return 'category-default'

def _format_enrichment_data(ip_data: Dict[str, Any]) -> str:
    if ip_data.get('error'):
        return f"Enrichment Error: {ip_data.get('error')}"
    
    parts = []
    if ip_data.get('country'): parts.append(f"Country: {ip_data.get('country')}")
    if ip_data.get('city'): parts.append(f"City: {ip_data.get('city')}")
    if ip_data.get('as'): parts.append(f"AS: {ip_data.get('as')}")
    
    return " | ".join(parts)

class ReportGenerator:
    
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
        try:
            report_logger.info(f"Generating report components for project: {project_name}")
            
            normalized_data, stats = self._prepare_report_data(findings) 
            
            category_options = self._generate_category_options(stats)
            file_options = self._generate_file_options(normalized_data)
            indicators_table = self._generate_indicators_table(normalized_data, enriched_ips)
            
            generation_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            template = self._get_html_template()
            
            report_html = template.format(
                project_name=project_name,
                generation_date=generation_date,
                stats_cards=self._generate_stats_cards(stats),
                category_options=category_options,
                file_options=file_options,
                total_indicators=len(normalized_data),
                indicators_table=indicators_table
            )
            
            report_logger.info(f"Report HTML generated successfully for {project_name}")
            return report_html
            
        except Exception as e:
            report_logger.error(f"Critical error generating report: {e}", exc_info=True)
            raise

    def _prepare_report_data(self, findings: Dict[str, Dict[str, Any]]):
        normalized_data = []
        stats = {'total': 0, 'files': set()}
        
        for category, items in findings.items():
            if category == 'Processing_Summary':
                stats['summary'] = items
                continue

            for value, context_str in items.items():
                stats[category] = stats.get(category, 0) + 1
                stats['total'] += 1

                file_source = "Unknown"
                position = "N/A"
                
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
                    'position': position
                })
        
        return normalized_data, stats
    
    def _generate_stats_cards(self, stats: Dict[str, Any]) -> str:
        cards = []
        category_counts = sorted([(k, v) for k, v in stats.items() if k not in ['total', 'summary', 'files']], key=lambda x: x[1], reverse=True)
        
        for category, count in category_counts[:4]:
            cards.append(f'<div class="stat-card"><h3>{count}</h3><p>{category.replace("_", " ")}</p></div>')
        
        cards.append(f'<div class="stat-card"><h3>{stats.get("total", 0)}</h3><p>Total Indicators</p></div>')
             
        return ''.join(cards)
    
    def _generate_category_options(self, stats: Dict[str, Any]) -> str:
        options = []
        valid_categories = sorted([k for k in stats.keys() if k not in ['total', 'summary', 'files']])
        
        for category in valid_categories:
            options.append(f'<option value="{category}">{category.replace("_", " ").title()} ({stats[category]})</option>')
        return ''.join(options)
    
    def _generate_file_options(self, normalized_data: List[Dict[str, Any]]) -> str:
        file_counts = {}
        for item in normalized_data:
             file_counts[item['file_source']] = file_counts.get(item['file_source'], 0) + 1
             
        options = []
        for file in sorted(file_counts.keys()):
            options.append(f'<option value="{file}">{file} ({file_counts[file]})</option>')
        return ''.join(options)
    
    def _generate_indicators_table(self, normalized_data: List[Dict[str, Any]], enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        if not normalized_data:
            return '<div class="no-data">No indicators found</div>'
        
        table_html = """
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Value</th>
                    <th>Details / Enrichment</th>
                    <th>File Source</th>
                    <th>Position</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for item in normalized_data:
            details = ""
            if ('IPv4' in item['category'] or 'IPv6' in item['category']) and enriched_ips and item['value'] in enriched_ips:
                details = _format_enrichment_data(enriched_ips[item['value']])

            category_class = _get_category_badge_class(item['category'])
            
            table_html += f"""
                <tr>
                    <td><span class="category-badge {category_class}">{item['category'].replace('_', ' ')}</span></td>
                    <td><span class="indicator-value">{item['value']}</span></td>
                    <td><span class="details-info">{details}</span></td>
                    <td><span class="file-source">{item['file_source']}</span></td>
                    <td>{item['position']}</td>
                </tr>
                """
        
        table_html += "</tbody></table>"
        return table_html
        
    def _get_html_template(self):
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
        .stat-card h3 {{ margin: 0; font-size: 24px; }}
        .stat-card p {{ margin: 5px 0 0 0; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        .category-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .category-ip {{ background-color: #e3f2fd; color: #1976d2; }}
        .category-email {{ background-color: #f3e5f5; color: #7b1fa2; }}
        .category-url {{ background-color: #e8f5e8; color: #388e3c; }}
        .category-hash {{ background-color: #fdf3e3; color: #ff9800; }}
        .category-financial {{ background-color: #fff3e0; color: #f57c00; }}
        .category-default {{ background-color: #f5f5f5; color: #666; }}
        .indicator-value {{ font-family: monospace; background-color: #f0f0f0; padding: 2px 4px; border-radius: 3px; }}
        .file-source, .details-info {{ color: #666; font-size: 12px; }}
        .controls-section {{ padding: 15px; background: #f8f9fa; border-radius: 8px; margin-bottom: 20px; display: flex; gap: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Intelligence Report: {project_name}</h1>
        <p>Generated on: {generation_date}</p>
        <div class="stats-section">{stats_cards}</div>
        <div class="data-section">
            <h2>All Indicators</h2>
            <div class="controls-section">
                <div>
                    <label for="categoryFilter">Category:</label>
                    <select id="categoryFilter" onchange="filterData()">
                        <option value="">All</option>{category_options}
                    </select>
                </div>
                <div>
                    <label for="fileFilter">File:</label>
                    <select id="fileFilter" onchange="filterData()">
                        <option value="">All</option>{file_options}
                    </select>
                </div>
                <div>
                    <label for="searchFilter">Search:</label>
                    <input type="text" id="searchFilter" onkeyup="filterData()">
                </div>
            </div>
            <div id="indicatorsTable">{indicators_table}</div>
        </div>
    </div>
    <script>
        function filterData() {{
            const category = document.getElementById('categoryFilter').value.toLowerCase();
            const file = document.getElementById('fileFilter').value;
            const search = document.getElementById('searchFilter').value.toLowerCase();
            const table = document.querySelector('#indicatorsTable table tbody');
            const rows = table.querySelectorAll('tr');
            rows.forEach(row => {{
                const rowCategory = row.cells[0].textContent.toLowerCase();
                const rowValue = row.cells[1].textContent.toLowerCase();
                const rowFile = row.cells[3].textContent;
                const show = (!category || rowCategory.includes(category)) &&
                             (!file || rowFile === file) &&
                             (!search || rowValue.includes(search));
                row.style.display = show ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
        """