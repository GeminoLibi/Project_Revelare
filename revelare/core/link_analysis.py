import json
import os
import networkx as nx
import logging
from typing import Dict, List, Any, Optional
import glob

from revelare.utils.logger import get_logger

logger = get_logger(__name__)

class LinkAnalysisService:
    def __init__(self, cases_dir: str):
        self.cases_dir = cases_dir
        self.graph = nx.Graph()
        self._build_cross_case_graph()

    def _build_cross_case_graph(self):
        """
        Scans all case directories, reads indicators.json, and builds a NetworkX graph.
        Nodes: Cases and Indicators
        Edges: Case -> Indicator
        """
        logger.info("Building cross-case link analysis graph...")
        self.graph.clear()
        
        # Find all indicators.json files in any subdirectory of cases_dir
        # Structure is usually: cases_dir/CASE_NAME/indicators.json or exports/.../indicators.json
        # We need to be careful to identify the CASE NAME correctly.
        
        # Assuming standard structure: cases/CASE_NAME/indicators.json
        # Or cases/CASE_NAME/exports/CASE_NAME_report.../indicators.json
        
        # Let's search for all indicators.json
        pattern = os.path.join(self.cases_dir, "**", "indicators.json")
        indicator_files = glob.glob(pattern, recursive=True)
        
        for file_path in indicator_files:
            try:
                # Infer case name from path
                # Path: .../cases/CASE_NAME/.../indicators.json
                parts = os.path.normpath(file_path).split(os.sep)
                if 'cases' in parts:
                    idx = parts.index('cases')
                    if idx + 1 < len(parts):
                        case_name = parts[idx + 1]
                    else:
                        continue
                else:
                    # Fallback
                    case_name = os.path.basename(os.path.dirname(os.path.dirname(file_path)))
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    indicators = json.load(f)
                
                # Add Case Node
                self.graph.add_node(case_name, type='case', label=case_name)
                
                # Add Indicator Nodes and Edges
                # Focus on strong selectors: Email, Phone, IP (maybe), Hash
                target_categories = ['Email_Addresses', 'Phone_Numbers', 'Bitcoin_Addresses', 'Credit_Card_Numbers', 'MD5_Hashes', 'Device_IDs_UUIDs']
                
                for category, items in indicators.items():
                    if category not in target_categories:
                        continue
                        
                    for indicator, context in items.items():
                        # Add Indicator Node
                        self.graph.add_node(indicator, type='indicator', category=category, label=indicator)
                        
                        # Add Edge (Case <-> Indicator)
                        self.graph.add_edge(case_name, indicator, weight=1)
                        
            except Exception as e:
                logger.error(f"Error processing {file_path} for link analysis: {e}")

        logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")

    def get_links_for_case(self, case_name: str, depth: int = 2) -> Dict[str, Any]:
        """
        Returns a subgraph centered on a specific case.
        """
        if case_name not in self.graph:
            return {"nodes": [], "edges": []}
            
        # Get ego graph
        subgraph = nx.ego_graph(self.graph, case_name, radius=depth)
        return nx.node_link_data(subgraph)

    def get_common_links(self) -> Dict[str, Any]:
        """
        Returns indicators that are connected to > 1 case (bridges).
        """
        bridge_nodes = []
        for node, attr in self.graph.nodes(data=True):
            if attr.get('type') == 'indicator':
                neighbors = list(self.graph.neighbors(node))
                cases = [n for n in neighbors if self.graph.nodes[n].get('type') == 'case']
                if len(cases) > 1:
                    bridge_nodes.append({
                        "indicator": node,
                        "category": attr.get('category'),
                        "cases": cases
                    })
        
        return bridge_nodes
    
    def export_graph_json(self) -> Dict[str, Any]:
        return nx.node_link_data(self.graph)

