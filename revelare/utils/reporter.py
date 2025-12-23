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
    
    def _generate_timeline_view(self, normalized_data: List[Dict[str, Any]]) -> str:
        """
        Generates an HTML timeline view for extracted timestamps.
        """
        timestamps = []
        for item in normalized_data:
            if item['category'] == 'Timestamps' or item['category'] == 'ISO_Timestamps' or item['category'] == 'Unix_Timestamps':
                try:
                    # Parse timestamp (simplified)
                    val = item['value']
                    # Try to normalize to sortable format
                    timestamps.append({
                        'raw': val,
                        'file': item['file_source'],
                        'details': item['position'] if item['position'] != 'N/A' else 'Extracted'
                    })
                except:
                    pass
        
        # Sort if possible (naive string sort for now, ideally parse dates)
        timestamps.sort(key=lambda x: x['raw'])
        
        if not timestamps:
            return ""

        timeline_html = """
        <div id="timeline" class="section">
            <h2 class="section-title">Timeline Analysis</h2>
            <div class="timeline">
        """
        
        for ts in timestamps:
            timeline_html += f"""
                <div class="timeline-item">
                    <div class="timeline-date">{ts['raw']}</div>
                    <div class="timeline-content">
                        <strong>{ts['file']}</strong><br>
                        <span class="text-muted">{ts['details']}</span>
                    </div>
                </div>
            """
            
        timeline_html += """
            </div>
        </div>
        """
        return timeline_html

    def generate_report(self, project_name: str, findings: Dict[str, Dict[str, Any]], 
                        enriched_ips: Dict[str, Dict[str, Any]] = None) -> str:
        try:
            report_logger.info(f"Generating report components for project: {project_name}")
            
            normalized_data, stats = self._prepare_report_data(findings) 
            
            category_options = self._generate_category_options(stats)
            file_options = self._generate_file_options(normalized_data)
            indicators_table = self._generate_indicators_table(normalized_data, enriched_ips)
            timeline_view = self._generate_timeline_view(normalized_data)
            map_view = self._generate_map_view(normalized_data)
            
            generation_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            template = self._get_html_template()
            
            report_html = template.format(
                project_name=project_name,
                generation_date=generation_date,
                stats_cards=self._generate_stats_cards(stats),
                category_options=category_options,
                file_options=file_options,
                total_indicators=len(normalized_data),
                indicators_table=indicators_table,
                timeline_section=timeline_view,
                map_section=map_view
            )
            
            report_logger.info(f"Report HTML generated successfully for {project_name}")
            return report_html
            
        except Exception as e:
            report_logger.error(f"Critical error generating report: {e}", exc_info=True)
            raise

    def _generate_map_view(self, normalized_data: List[Dict[str, Any]]) -> str:
        """
        Generates a Leaflet map section if GPS coordinates are found.
        """
        markers = []
        for item in normalized_data:
            if item['category'] == 'GPS_Coordinates':
                try:
                    lat, lon = map(str.strip, item['value'].split(','))
                    markers.append({
                        'lat': float(lat), 
                        'lon': float(lon), 
                        'popup': f"File: {item['file_source']}<br>Coords: {item['value']}"
                    })
                except:
                    pass
        
        if not markers:
            return ""

        map_html = """
        <div id="geographic" class="section">
            <h2 class="section-title">Geospatial Analysis</h2>
            <div class="map-container">
                <div id="map" style="height: 500px; width: 100%;"></div>
            </div>
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
            <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var map = L.map('map').setView([0, 0], 2);
                    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        maxZoom: 19,
                        attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                    }).addTo(map);

                    var markers = %s;
                    var bounds = L.latLngBounds();

                    markers.forEach(function(m) {
                        var marker = L.marker([m.lat, m.lon]).addTo(map);
                        marker.bindPopup(m.popup);
                        bounds.extend(marker.getLatLng());
                    });

                    if (markers.length > 0) {
                        map.fitBounds(bounds, {padding: [50, 50]});
                    }
                });
            </script>
        </div>
        """ % json.dumps(markers)
        
        return map_html

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
        total = stats.get("total", 0)
        files_count = len(stats.get("files", set()))
        
        # Main stats
        cards.append(f'<div class="stat-card"><h3>{total}</h3><p>Total Indicators</p></div>')
        cards.append(f'<div class="stat-card"><h3>{files_count}</h3><p>Files Processed</p></div>')
        
        # Top categories
        category_counts = sorted([(k, v) for k, v in stats.items() if k not in ['total', 'summary', 'files']], key=lambda x: x[1], reverse=True)
        for category, count in category_counts[:2]:
            cards.append(f'<div class="stat-card"><h3>{count}</h3><p>{category.replace("_", " ").title()}</p></div>')
             
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
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 0; 
            background-color: #f5f5f5; 
            line-height: 1.6;
        }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 2em; }}
        .header p {{ margin: 0; opacity: 0.9; }}
        .nav-bar {{
            background: white;
            padding: 15px 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .nav-links {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        .nav-link {{
            color: #667eea;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 5px;
            transition: background 0.2s;
        }}
        .nav-link:hover {{
            background: #f0f0f0;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            margin-top: 20px;
            margin-bottom: 20px;
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }}
        .section {{ margin-bottom: 40px; }}
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            color: #333;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{ 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 2.5em; color: #667eea; }}
        .stat-card p {{ margin: 0; color: #666; font-size: 0.9em; }}
        .controls-section {{ 
            padding: 20px; 
            background: #f8f9fa; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .control-group {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}
        .control-group label {{
            font-weight: 600;
            color: #333;
            font-size: 0.9em;
        }}
        .control-group select, .control-group input {{
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 0.95em;
        }}
        .control-group select:focus, .control-group input:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            background: white;
        }}
        th, td {{ 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e0e0e0; 
        }}
        th {{ 
            background-color: #667eea;
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        tbody tr:hover {{
            background-color: #f8f9fa;
        }}
        .category-badge {{ 
            padding: 4px 10px; 
            border-radius: 4px; 
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
        }}
        .category-ip {{ background-color: #e3f2fd; color: #1976d2; }}
        .category-email {{ background-color: #f3e5f5; color: #7b1fa2; }}
        .category-url {{ background-color: #e8f5e8; color: #388e3c; }}
        .category-hash {{ background-color: #fdf3e3; color: #ff9800; }}
        .category-financial {{ background-color: #fff3e0; color: #f57c00; }}
        .category-default {{ background-color: #f5f5f5; color: #666; }}
        .indicator-value {{ 
            font-family: 'Courier New', monospace; 
            background-color: #f0f0f0; 
            padding: 4px 8px; 
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .file-source, .details-info {{ 
            color: #666; 
            font-size: 0.85em;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            padding: 20px;
            margin-top: 20px;
        }}
        .pagination button {{
            padding: 8px 15px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .pagination button:hover:not(:disabled) {{
            background: #667eea;
            color: white;
            border-color: #667eea;
        }}
        .pagination button.active {{
            background: #667eea;
            color: white;
            border-color: #667eea;
        }}
        .pagination button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .stats-info {{
            text-align: center;
            color: #666;
            margin: 15px 0;
            font-size: 0.9em;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #999;
        }}
        .timeline {{ 
            position: relative; 
            max-width: 100%; 
            margin: 20px auto; 
            padding-left: 30px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            width: 3px;
            background-color: #667eea;
            top: 0;
            bottom: 0;
            left: 10px;
        }}
        .timeline-item {{ 
            padding: 15px 20px 15px 40px; 
            position: relative; 
            background: white;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .timeline-item::before {{
            content: '';
            position: absolute;
            width: 12px;
            height: 12px;
            background: #667eea;
            border-radius: 50%;
            left: 4px;
            top: 20px;
            border: 3px solid white;
            box-shadow: 0 0 0 2px #667eea;
        }}
        .timeline-date {{ 
            font-weight: bold; 
            margin-bottom: 5px; 
            color: #667eea; 
        }}
        .timeline-content {{ 
            color: #666;
        }}
        .map-container {{
            margin: 20px 0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        @media print {{
            .nav-bar {{ display: none; }}
            .controls-section {{ display: none; }}
            .pagination {{ display: none; }}
        }}
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            .controls-section {{
                grid-template-columns: 1fr;
            }}
            table {{
                font-size: 0.85em;
            }}
            th, td {{
                padding: 8px;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Intelligence Report: {project_name}</h1>
        <p>Generated on: {generation_date}</p>
    </div>
    
    <div class="nav-bar">
        <div class="nav-links">
            <a href="#summary" class="nav-link">Summary</a>
            <a href="#indicators" class="nav-link">Indicators</a>
            <a href="#timeline" class="nav-link">Timeline</a>
            <a href="#geographic" class="nav-link">Geographic</a>
        </div>
    </div>

    <div class="container">
        <div id="summary" class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="stats-grid">
                {stats_cards}
            </div>
        </div>
        
        {map_section}

        {timeline_section}
        
        <div id="indicators" class="section">
            <h2 class="section-title">All Indicators</h2>
            <div class="controls-section">
                <div class="control-group">
                    <label for="categoryFilter">Category:</label>
                    <select id="categoryFilter" onchange="filterAndPaginate()">
                        <option value="">All Categories</option>{category_options}
                    </select>
                </div>
                <div class="control-group">
                    <label for="fileFilter">File:</label>
                    <select id="fileFilter" onchange="filterAndPaginate()">
                        <option value="">All Files</option>{file_options}
                    </select>
                </div>
                <div class="control-group">
                    <label for="searchFilter">Search:</label>
                    <input type="text" id="searchFilter" placeholder="Search values..." onkeyup="filterAndPaginate()">
                </div>
                <div class="control-group">
                    <label for="pageSize">Items per page:</label>
                    <select id="pageSize" onchange="changePageSize()">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                        <option value="200">200</option>
                    </select>
                </div>
            </div>
            <div class="stats-info" id="statsInfo">Loading...</div>
            <div id="indicatorsTable">{indicators_table}</div>
            <div id="pagination"></div>
        </div>
    </div>
    <script>
        let allRows = [];
        let filteredRows = [];
        let currentPage = 1;
        let pageSize = 50;

        function initData() {{
            const table = document.querySelector('#indicatorsTable table tbody');
            if (!table) return;
            allRows = Array.from(table.querySelectorAll('tr'));
            filteredRows = allRows.slice();
            filterAndPaginate();
        }}

        function filterAndPaginate() {{
            const category = document.getElementById('categoryFilter').value.toLowerCase();
            const file = document.getElementById('fileFilter').value;
            const search = document.getElementById('searchFilter').value.toLowerCase();
            
            filteredRows = allRows.filter(row => {{
                if (!row.cells || row.cells.length < 4) return false;
                const rowCategory = (row.cells[0].textContent || '').toLowerCase();
                const rowValue = (row.cells[1].textContent || '').toLowerCase();
                const rowFile = row.cells[3].textContent || '';
                const rowDetails = (row.cells[2].textContent || '').toLowerCase();
                
                const matchCategory = !category || rowCategory.includes(category);
                const matchFile = !file || rowFile === file;
                const matchSearch = !search || rowValue.includes(search) || rowDetails.includes(search);
                
                return matchCategory && matchFile && matchSearch;
            }});
            
            currentPage = 1;
            renderPage();
        }}

        function renderPage() {{
            const table = document.querySelector('#indicatorsTable table tbody');
            if (!table) return;
            
            const totalPages = Math.ceil(filteredRows.length / pageSize);
            const startIdx = (currentPage - 1) * pageSize;
            const endIdx = Math.min(startIdx + pageSize, filteredRows.length);
            
            // Hide all rows
            allRows.forEach(row => row.style.display = 'none');
            
            // Show filtered rows for current page
            filteredRows.slice(startIdx, endIdx).forEach(row => {{
                row.style.display = '';
            }});
            
            // Update stats
            const statsEl = document.getElementById('statsInfo');
            if (statsEl) {{
                const showing = filteredRows.length > 0 ? `${{startIdx + 1}}-${{endIdx}}` : '0';
                statsEl.textContent = `Showing ${{showing}} of ${{filteredRows.length}} indicators (out of ${{allRows.length}} total)`;
            }}
            
            // Render pagination
            renderPagination(totalPages);
        }}

        function renderPagination(totalPages) {{
            const paginationEl = document.getElementById('pagination');
            if (!paginationEl) return;
            
            if (totalPages <= 1) {{
                paginationEl.innerHTML = '';
                return;
            }}
            
            let html = '<div class="pagination">';
            
            // Previous
            html += `<button ${{currentPage === 1 ? 'disabled' : ''}} onclick="goToPage(${{currentPage - 1}})">‹ Prev</button>`;
            
            // Page numbers
            const maxVisible = 7;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
            let endPage = Math.min(totalPages, startPage + maxVisible - 1);
            if (endPage - startPage < maxVisible - 1) {{
                startPage = Math.max(1, endPage - maxVisible + 1);
            }}
            
            if (startPage > 1) {{
                html += `<button onclick="goToPage(1)">1</button>`;
                if (startPage > 2) html += `<span>...</span>`;
            }}
            
            for (let i = startPage; i <= endPage; i++) {{
                html += `<button class="${{i === currentPage ? 'active' : ''}}" onclick="goToPage(${{i}})">${{i}}</button>`;
            }}
            
            if (endPage < totalPages) {{
                if (endPage < totalPages - 1) html += `<span>...</span>`;
                html += `<button onclick="goToPage(${{totalPages}})">${{totalPages}}</button>`;
            }}
            
            // Next
            html += `<button ${{currentPage === totalPages ? 'disabled' : ''}} onclick="goToPage(${{currentPage + 1}})">Next ›</button>`;
            
            html += '</div>';
            paginationEl.innerHTML = html;
        }}

        function goToPage(page) {{
            const totalPages = Math.ceil(filteredRows.length / pageSize);
            if (page >= 1 && page <= totalPages) {{
                currentPage = page;
                renderPage();
                document.getElementById('indicators').scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }}
        }}

        function changePageSize() {{
            pageSize = parseInt(document.getElementById('pageSize').value);
            currentPage = 1;
            renderPage();
        }}

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {{
                    target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                }}
            }});
        }});

        // Initialize on load
        window.addEventListener('DOMContentLoaded', initData);
    </script>
</body>
</html>
        """