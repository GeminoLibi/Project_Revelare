import os
import json
import networkx as nx
from datetime import datetime, timezone
from typing import Dict, List, Any
from collections import Counter

from revelare.utils.logger import get_logger
from revelare.core.link_analysis import LinkAnalysisService

logger = get_logger(__name__)

class GlobalReporter:
    def __init__(self, cases_dir: str):
        self.cases_dir = cases_dir
        self.link_service = LinkAnalysisService(cases_dir)

    def generate_dashboard(self, output_path: str = None):
        """
        Generates a master dashboard HTML file linking all cases and visualizing the network.
        """
        if output_path is None:
            output_path = os.path.join(self.cases_dir, "investigation_dashboard.html")

        logger.info(f"Generating global dashboard at {output_path}")

        # 1. Gather stats from all cases
        cases_data = self._scan_cases()
        
        # 2. Generate Network Graph Data (Nodes/Edges for Vis.js)
        graph_data = self._prepare_graph_data()

        # 3. Calculate Global Stats
        total_indicators = sum(c['indicator_count'] for c in cases_data)
        total_files = sum(c['file_count'] for c in cases_data)
        top_indicators = self._get_top_indicators()

        html = self._render_template(
            cases=cases_data,
            graph_data=json.dumps(graph_data),
            stats={
                'case_count': len(cases_data),
                'indicator_count': total_indicators,
                'file_count': total_files,
                'generated_at': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            },
            top_indicators=top_indicators
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info("Dashboard generated successfully.")

    def _scan_cases(self) -> List[Dict[str, Any]]:
        cases = []
        # Look for case directories
        for entry in os.listdir(self.cases_dir):
            case_path = os.path.join(self.cases_dir, entry)
            if not os.path.isdir(case_path):
                continue
            
            # Check if it's a valid case (has report or metadata)
            report_path = os.path.join(case_path, f"{entry}_report.html")
            json_path = os.path.join(case_path, "indicators.json")
            
            if os.path.exists(report_path) or os.path.exists(json_path):
                # Gather basic stats
                ind_count = 0
                file_count = 0
                
                if os.path.exists(json_path):
                    try:
                        with open(json_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            # Count indicators
                            for cat, items in data.items():
                                if isinstance(items, dict):
                                    ind_count += len(items)
                            
                            # Try to get file count from summary
                            if 'Processing_Summary' in data:
                                file_count = int(data['Processing_Summary'].get('Total_Files_Processed', 0))
                    except:
                        pass
                
                cases.append({
                    'name': entry,
                    'path': f"./{entry}/{entry}_report.html",
                    'indicator_count': ind_count,
                    'file_count': file_count,
                    'status': 'Processed'
                })
        
        return sorted(cases, key=lambda x: x['name'])

    def _prepare_graph_data(self) -> Dict[str, Any]:
        """Convert NetworkX graph to Vis.js format"""
        g = self.link_service.graph
        nodes = []
        edges = []
        
        for n, attr in g.nodes(data=True):
            node_type = attr.get('type', 'unknown')
            
            # Vis.js node properties
            node = {
                'id': n,
                'label': attr.get('label', n),
                'group': node_type
            }
            
            if node_type == 'case':
                node['value'] = 20  # Bigger size
                node['color'] = '#007bff'
                node['shape'] = 'box'
            else:
                node['value'] = 5
                node['color'] = '#28a745' if attr.get('category') == 'Email_Addresses' else '#ffc107'
            
            nodes.append(node)
            
        for u, v, attr in g.edges(data=True):
            edges.append({
                'from': u,
                'to': v
            })
            
        return {'nodes': nodes, 'edges': edges}

    def _get_top_indicators(self) -> List[Dict[str, Any]]:
        """Find indicators connected to multiple cases"""
        g = self.link_service.graph
        counts = []
        
        for n, attr in g.nodes(data=True):
            if attr.get('type') == 'indicator':
                degree = g.degree(n)
                if degree > 1:
                    counts.append({
                        'value': n,
                        'count': degree,
                        'category': attr.get('category', 'Unknown')
                    })
        
        return sorted(counts, key=lambda x: x['count'], reverse=True)[:10]

    def _render_template(self, cases, graph_data, stats, top_indicators) -> str:
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Revelare Master Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {{ --primary: #2c3e50; --secondary: #34495e; --accent: #3498db; --bg: #ecf0f1; --card: #fff; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--primary); }}
        .header {{ background: var(--primary); color: #fff; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ margin: 0; font-size: 1.5rem; }}
        .container {{ max-width: 1400px; margin: 2rem auto; padding: 0 1rem; display: grid; grid-template-columns: 300px 1fr; gap: 2rem; }}
        
        .sidebar {{ display: flex; flex-direction: column; gap: 1.5rem; }}
        .main-content {{ display: flex; flex-direction: column; gap: 1.5rem; }}
        
        .card {{ background: var(--card); border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); padding: 1.5rem; }}
        .card h2 {{ margin-top: 0; font-size: 1.2rem; border-bottom: 2px solid var(--bg); padding-bottom: 0.5rem; color: var(--secondary); }}
        
        .stat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 1rem; }}
        .stat-item {{ background: var(--bg); padding: 1rem; border-radius: 6px; text-align: center; }}
        .stat-val {{ display: block; font-size: 1.8rem; font-weight: bold; color: var(--accent); }}
        .stat-label {{ font-size: 0.85rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; }}
        
        .case-list {{ list-style: none; padding: 0; margin: 0; max-height: 400px; overflow-y: auto; }}
        .case-item {{ padding: 0.8rem; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }}
        .case-item:last-child {{ border-bottom: none; }}
        .case-link {{ text-decoration: none; color: var(--primary); font-weight: 500; display: block; }}
        .case-link:hover {{ color: var(--accent); }}
        .case-meta {{ font-size: 0.8rem; color: #95a5a6; }}
        
        .network-container {{ height: 600px; border: 1px solid #eee; border-radius: 4px; background: #fdfdfd; }}
        
        .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; background: #eee; }}
        .badge-indicators {{ background: #e8f6f3; color: #16a085; }}
        
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 0.8rem; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-network-wired"></i> Revelare Dashboard</h1>
        <span>Generated: {stats['generated_at']}</span>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <div class="card">
                <h2>Overview</h2>
                <div class="stat-grid">
                    <div class="stat-item">
                        <span class="stat-val">{stats['case_count']}</span>
                        <span class="stat-label">Cases</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-val">{stats['indicator_count']}</span>
                        <span class="stat-label">Indicators</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-val">{stats['file_count']}</span>
                        <span class="stat-label">Files</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-val">{len(top_indicators)}</span>
                        <span class="stat-label">Links</span>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Case Files</h2>
                <ul class="case-list">
                    {''.join(f'''
                    <li class="case-item">
                        <div>
                            <a href="{c['path']}" class="case-link" target="_blank">{c['name']}</a>
                            <span class="case-meta">{c['file_count']} files processed</span>
                        </div>
                        <span class="badge badge-indicators">{c['indicator_count']} ind.</span>
                    </li>
                    ''' for c in cases)}
                </ul>
            </div>
        </div>
        
        <div class="main-content">
            <div class="card">
                <h2>Cross-Case Link Analysis</h2>
                <p style="font-size: 0.9rem; color: #666; margin-bottom: 1rem;">
                    Visualizing connections between cases. Blue squares are cases; colored dots are shared indicators (Email, IP, Phone).
                </p>
                <div id="mynetwork" class="network-container"></div>
            </div>
            
            <div class="card">
                <h2>Top Connected Indicators</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Indicator</th>
                            <th>Category</th>
                            <th>Connections</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(f'''
                        <tr>
                            <td style="font-family: monospace;">{i['value']}</td>
                            <td>{i['category']}</td>
                            <td>{i['count']} cases</td>
                        </tr>
                        ''' for i in top_indicators) if top_indicators else '<tr><td colspan="3">No cross-case connections found yet.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script type="text/javascript">
        // Network Graph Data
        var data = {graph_data};
        
        var container = document.getElementById('mynetwork');
        var options = {{
            nodes: {{
                shape: 'dot',
                size: 10,
                font: {{ size: 12, face: 'Tahoma' }}
            }},
            edges: {{
                width: 0.5,
                color: {{ inherit: 'from' }},
                smooth: {{ type: 'continuous' }}
            }},
            physics: {{
                stabilization: false,
                barnesHut: {{
                    gravitationalConstant: -2000,
                    springConstant: 0.04,
                    springLength: 95
                }}
            }},
            interaction: {{
                tooltipDelay: 200,
                hideEdgesOnDrag: true
            }}
        }};
        
        var network = new vis.Network(container, data, options);
        
        network.on("click", function (params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = data.nodes.find(n => n.id === nodeId);
                if (node && node.group === 'case') {{
                    // Open case report on click
                    // We need to map node label back to path, or just assume standard path
                    console.log("Clicked case: " + node.label);
                }}
            }}
        }});
    </script>
</body>
</html>
"""

