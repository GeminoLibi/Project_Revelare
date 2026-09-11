"""
Cross-case identifier corpus builder for subject/identifier linkage exports.

Builds subject-centric tables and connection graphs from case findings without
requiring AI. Unknown or missing values are exported as null.
"""
import csv
import io
import json
import os
import re
import sqlite3
import zipfile
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

CASE_FOLDER_PATTERN = re.compile(r'^\d{6,}[_\-\s]')

from revelare.config.config import Config
from revelare.core.case_taxonomy import collect_filter_options, enrich_case_record
from revelare.core.database import list_db_cases
from revelare.utils.logger import get_logger

logger = get_logger(__name__)

PRIMARY_CASE = "__case__"

# Preferred display order for corpus exports
DEFAULT_COLUMN_TYPES = [
    "Subject_Names",
    "Email_Addresses",
    "Phone_Numbers",
    "IPv4",
    "URLs",
    "Bitcoin_Addresses",
    "Ethereum_Addresses",
    "Credit_Card_Numbers",
    "SSN",
    "Device_IDs_UUIDs",
    "MAC_Addresses",
    "Onion_Addresses",
    "IBAN",
]

# Friendly column headers for wide exports
COLUMN_LABELS = {
    PRIMARY_CASE: "subject_case",
    "Subject_Names": "subject_names",
    "Email_Addresses": "emails",
    "Phone_Numbers": "phones",
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "URLs": "urls",
    "Bitcoin_Addresses": "bitcoin",
    "Ethereum_Addresses": "ethereum",
    "Monero_Addresses": "monero",
    "Credit_Card_Numbers": "credit_cards",
    "Credit_Card_VisaMcDiscover": "credit_cards_visa_mc",
    "Credit_Card_Amex": "credit_cards_amex",
    "SSN": "ssn",
    "Device_IDs_UUIDs": "device_ids",
    "MAC_Addresses": "mac_addresses",
    "Onion_Addresses": "onion_addresses",
    "IBAN": "iban",
    "User_Agents": "user_agents",
    "GPS_Coordinates": "gps_coordinates",
    "ISO_Timestamps": "timestamps",
}


def _label_for_type(indicator_type: str) -> str:
    if indicator_type == PRIMARY_CASE:
        return "subject_case"
    return COLUMN_LABELS.get(indicator_type, indicator_type.lower())


def _normalize_values(values: Set[str]) -> Optional[List[str]]:
    if not values:
        return None
    return sorted(values)


def _looks_like_case_folder(name: str) -> bool:
    return bool(CASE_FOLDER_PATTERN.match(name))


def _has_evidence_subdir(path: str) -> bool:
    try:
        for item in os.listdir(path):
            if item.lower() == 'evidence' and os.path.isdir(os.path.join(path, item)):
                return True
    except OSError:
        pass
    return False


def _has_case_content(path: str) -> bool:
    try:
        for item in os.listdir(path):
            if item.startswith('.'):
                continue
            full = os.path.join(path, item)
            if os.path.isfile(full) or os.path.isdir(full):
                return True
    except OSError:
        pass
    return False


def _is_external_case_candidate(path: str, filenames: List[str]) -> bool:
    if 'raw_findings.json' in filenames:
        return True
    name = os.path.basename(path)
    if not _looks_like_case_folder(name):
        return False
    return _has_evidence_subdir(path) or _has_case_content(path)


def _append_db_source(source: Optional[str]) -> str:
    current = source or ""
    if current == "db" or "+db" in current:
        return current
    return f"{current}+db" if current else "db"


class CorpusBuilder:
    """Build subject-linked identifier corpora from Revelare case data."""

    def __init__(
        self,
        cases_dir: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        self.cases_dir = cases_dir or Config.UPLOAD_FOLDER
        self.db_path = db_path or Config.DATABASE
        self._case_paths: Dict[str, str] = {}

    def _read_findings_stats(self, findings_file: str) -> Tuple[bool, int, Set[str]]:
        has_findings = os.path.exists(findings_file)
        indicator_count = 0
        categories: Set[str] = set()
        if has_findings:
            try:
                with open(findings_file, 'r', encoding='utf-8') as handle:
                    data = json.load(handle)
                for category, items in data.items():
                    if category != 'Processing_Summary' and isinstance(items, dict):
                        categories.add(category)
                        indicator_count += len(items)
            except Exception as exc:
                logger.warning('Could not read findings for %s: %s', findings_file, exc)
        return has_findings, indicator_count, categories

    def _scan_external_cases(
        self, cases_by_name: Dict[str, Dict[str, Any]], max_depth: int = 2
    ) -> None:
        for external_root in Config.get_external_cases_dirs():
            external_root = os.path.abspath(external_root)
            if not os.path.isdir(external_root):
                logger.warning('External cases directory not found: %s', external_root)
                continue

            for dirpath, dirnames, filenames in os.walk(external_root):
                rel = os.path.relpath(dirpath, external_root)
                depth = 0 if rel == '.' else rel.count(os.sep) + 1
                if depth > max_depth:
                    dirnames.clear()
                    continue
                if depth == 0:
                    continue

                name = os.path.basename(dirpath)
                if name.startswith('.'):
                    continue

                if not _is_external_case_candidate(dirpath, filenames):
                    continue

                existing = cases_by_name.get(name)
                if existing and existing.get('source') in ('filesystem', 'filesystem+db'):
                    self._case_paths.setdefault(name, existing['path'])
                    dirnames.clear()
                    continue

                findings_file = os.path.join(dirpath, 'raw_findings.json')
                has_findings, indicator_count, categories = self._read_findings_stats(findings_file)
                cases_by_name[name] = {
                    'name': name,
                    'path': dirpath,
                    'has_findings': has_findings,
                    'indicator_count': indicator_count,
                    'categories': sorted(categories),
                    'source': 'external',
                }
                self._case_paths[name] = dirpath
                dirnames.clear()

    def discover_cases(self) -> List[Dict[str, Any]]:
        cases_by_name: Dict[str, Dict[str, Any]] = {}
        self._case_paths = {}

        if os.path.isdir(self.cases_dir):
            for name in sorted(os.listdir(self.cases_dir)):
                path = os.path.join(self.cases_dir, name)
                if not os.path.isdir(path) or name.startswith("."):
                    continue

                findings_file = os.path.join(path, "raw_findings.json")
                has_findings, indicator_count, categories = self._read_findings_stats(findings_file)

                cases_by_name[name] = {
                    "name": name,
                    "path": path,
                    "has_findings": has_findings,
                    "indicator_count": indicator_count,
                    "categories": sorted(categories),
                    "source": "filesystem",
                }
                self._case_paths[name] = path

        self._scan_external_cases(cases_by_name)

        for name in list_db_cases():
            if name in cases_by_name:
                cases_by_name[name]["source"] = _append_db_source(
                    cases_by_name[name].get("source")
                )
                continue

        db_stats = self._load_db_case_stats()
        for name, stats in db_stats.items():
            if name in cases_by_name:
                cases_by_name[name]["indicator_count"] = max(
                    cases_by_name[name]["indicator_count"],
                    stats["indicator_count"],
                )
                merged_categories = set(cases_by_name[name]["categories"])
                merged_categories.update(stats["categories"])
                cases_by_name[name]["categories"] = sorted(merged_categories)
                cases_by_name[name]["has_findings"] = True
                cases_by_name[name]["source"] = _append_db_source(
                    cases_by_name[name].get("source")
                )
                continue

            db_path = self._case_paths.get(name, os.path.join(self.cases_dir, name))
            cases_by_name[name] = {
                "name": name,
                "path": db_path,
                "has_findings": stats["indicator_count"] > 0,
                "indicator_count": stats["indicator_count"],
                "categories": stats["categories"],
                "source": "db",
            }
            self._case_paths.setdefault(name, db_path)

        enriched = [enrich_case_record(case) for case in cases_by_name.values()]
        return sorted(enriched, key=lambda item: item["name"])

    def _load_db_case_stats(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.db_path):
            return {}

        stats: Dict[str, Dict[str, Any]] = {}
        try:
            conn = sqlite3.connect(self.db_path, timeout=60)
            conn.execute("PRAGMA busy_timeout=60000")
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT project_name, indicator_type, COUNT(DISTINCT indicator_value)
                FROM indicators
                GROUP BY project_name, indicator_type
                """
            )
            for project_name, indicator_type, count in cursor.fetchall():
                entry = stats.setdefault(
                    project_name,
                    {"indicator_count": 0, "categories": []},
                )
                entry["indicator_count"] += count
                entry["categories"].append(indicator_type)
            conn.close()
            for entry in stats.values():
                entry["categories"] = sorted(entry["categories"])
        except Exception as exc:
            logger.warning("DB stats lookup failed: %s", exc)
        return stats

    def get_available_identifier_types(self, case_names: Optional[List[str]] = None) -> List[str]:
        types: Set[str] = set()

        for case in self.discover_cases():
            if case_names and case["name"] not in case_names:
                continue
            types.update(case.get("categories", []))

        if case_names:
            db_types = self._load_types_from_db(case_names)
            types.update(db_types)

        ordered = [PRIMARY_CASE]
        for item in DEFAULT_COLUMN_TYPES:
            if item in types:
                ordered.append(item)
        for item in sorted(types):
            if item not in ordered:
                ordered.append(item)
        return ordered

    def _load_types_from_db(self, case_names: List[str]) -> Set[str]:
        if not os.path.exists(self.db_path) or not case_names:
            return set()

        placeholders = ", ".join("?" for _ in case_names)
        query = (
            f"SELECT DISTINCT indicator_type FROM indicators "
            f"WHERE project_name IN ({placeholders})"
        )
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            cursor = conn.cursor()
            cursor.execute(query, case_names)
            result = {row[0] for row in cursor.fetchall()}
            conn.close()
            return result
        except Exception as exc:
            logger.warning("DB type lookup failed: %s", exc)
            return set()

    def load_case_indicators(
        self, case_names: List[str]
    ) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Return {case_name: {category: {value: context}}}."""
        loaded: Dict[str, Dict[str, Dict[str, str]]] = {}

        if not self._case_paths:
            self.discover_cases()

        for case_name in case_names:
            case_path = self._case_paths.get(
                case_name, os.path.join(self.cases_dir, case_name)
            )
            findings_file = os.path.join(case_path, "raw_findings.json")
            if os.path.exists(findings_file):
                try:
                    with open(findings_file, "r", encoding="utf-8") as handle:
                        data = json.load(handle)
                    case_data: Dict[str, Dict[str, str]] = {}
                    for category, items in data.items():
                        if category == "Processing_Summary" or not isinstance(items, dict):
                            continue
                        case_data[category] = dict(items)
                    loaded[case_name] = case_data
                    continue
                except Exception as exc:
                    logger.warning("Findings load failed for %s: %s", case_name, exc)

            db_data = self._load_case_from_db(case_name)
            if db_data:
                loaded[case_name] = db_data

        return loaded

    def _load_case_from_db(self, case_name: str) -> Dict[str, Dict[str, str]]:
        if not os.path.exists(self.db_path):
            return {}

        try:
            conn = sqlite3.connect(self.db_path, timeout=60)
            conn.execute("PRAGMA busy_timeout=60000")
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT indicator_type, indicator_value
                FROM indicators
                WHERE project_name = ?
                GROUP BY indicator_type, indicator_value
                """,
                (case_name,),
            )
            case_data: Dict[str, Dict[str, str]] = defaultdict(dict)
            for indicator_type, value in cursor.fetchall():
                case_data[indicator_type][value] = ""
            conn.close()
            return dict(case_data)
        except Exception as exc:
            logger.warning("DB load failed for %s: %s", case_name, exc)
            return {}

    def build_corpus(
        self,
        case_names: List[str],
        primary_key: str,
        column_types: List[str],
        include_cross_links: bool = True,
    ) -> Dict[str, Any]:
        if not case_names:
            raise ValueError("Select at least one case.")

        if not column_types:
            column_types = [
                t for t in self.get_available_identifier_types(case_names) if t != PRIMARY_CASE
            ]

        case_data = self.load_case_indicators(case_names)
        missing = [name for name in case_names if name not in case_data]
        if missing:
            logger.warning("No indicator data for cases: %s", ", ".join(missing))

        if primary_key == PRIMARY_CASE:
            subjects, connections = self._build_case_primary(case_data, column_types)
        else:
            subjects, connections = self._build_identifier_primary(
                case_data, primary_key, column_types
            )

        cross_links: List[Dict[str, Any]] = []
        if include_cross_links:
            cross_links = self._build_cross_links(subjects, primary_key, column_types)

        nodes, edges = self._build_graph(subjects, connections, cross_links, primary_key)

        return {
            "meta": {
                "generated_at": datetime.now().isoformat(),
                "case_count": len(case_names),
                "cases": case_names,
                "primary_key": primary_key,
                "primary_label": _label_for_type(primary_key),
                "column_types": column_types,
                "subject_count": len(subjects),
                "connection_count": len(connections),
                "cross_link_count": len(cross_links),
            },
            "subjects": subjects,
            "connections": connections,
            "cross_links": cross_links,
            "graph": {"nodes": nodes, "edges": edges},
        }

    def _build_case_primary(
        self,
        case_data: Dict[str, Dict[str, Dict[str, str]]],
        column_types: List[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        subjects: List[Dict[str, Any]] = []
        connections: List[Dict[str, Any]] = []

        for case_name, categories in sorted(case_data.items()):
            row: Dict[str, Any] = {
                "subject_id": case_name,
                "primary_value": case_name,
                "primary_type": PRIMARY_CASE,
                "source_cases": [case_name],
            }

            for column_type in column_types:
                label = _label_for_type(column_type)
                values = set(categories.get(column_type, {}).keys())
                row[label] = _normalize_values(values)

            subjects.append(row)

            for column_type in column_types:
                label = _label_for_type(column_type)
                for value in categories.get(column_type, {}):
                    connections.append(
                        {
                            "subject_id": case_name,
                            "primary_value": case_name,
                            "primary_type": PRIMARY_CASE,
                            "linked_type": column_type,
                            "linked_value": value,
                            "source_case": case_name,
                            "relationship": "case_contains",
                        }
                    )

        return subjects, connections

    def _build_identifier_primary(
        self,
        case_data: Dict[str, Dict[str, Dict[str, str]]],
        primary_key: str,
        column_types: List[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        subject_map: Dict[str, Dict[str, Any]] = {}
        subject_cases: Dict[str, Set[str]] = defaultdict(set)
        subject_values: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        connections: List[Dict[str, Any]] = []

        for case_name, categories in case_data.items():
            primary_values = set(categories.get(primary_key, {}).keys())
            if not primary_values:
                continue

            case_values_by_type: Dict[str, Set[str]] = {}
            for column_type in column_types:
                if column_type == primary_key:
                    continue
                case_values_by_type[column_type] = set(
                    categories.get(column_type, {}).keys()
                )

            for primary_value in primary_values:
                subject_id = primary_value
                subject_cases[subject_id].add(case_name)

                if subject_id not in subject_map:
                    subject_map[subject_id] = {
                        "subject_id": subject_id,
                        "primary_value": primary_value,
                        "primary_type": primary_key,
                        _label_for_type(primary_key): primary_value,
                    }

                for column_type, values in case_values_by_type.items():
                    label = _label_for_type(column_type)
                    subject_values[subject_id][label].update(values)

                connections.append(
                    {
                        "subject_id": subject_id,
                        "primary_value": primary_value,
                        "primary_type": primary_key,
                        "linked_type": primary_key,
                        "linked_value": primary_value,
                        "source_case": case_name,
                        "relationship": "primary_in_case",
                    }
                )

                for column_type, values in case_values_by_type.items():
                    for value in values:
                        connections.append(
                            {
                                "subject_id": subject_id,
                                "primary_value": primary_value,
                                "primary_type": primary_key,
                                "linked_type": column_type,
                                "linked_value": value,
                                "source_case": case_name,
                                "relationship": "co_occurs_in_case",
                            }
                        )

        subjects: List[Dict[str, Any]] = []
        for subject_id, row in subject_map.items():
            row["source_cases"] = sorted(subject_cases[subject_id])
            for label, values in subject_values[subject_id].items():
                row[label] = _normalize_values(values)
            for column_type in column_types:
                if column_type == primary_key:
                    continue
                label = _label_for_type(column_type)
                if label not in row:
                    row[label] = None
            subjects.append(row)

        subjects.sort(key=lambda item: item["subject_id"])
        return subjects, connections

    def _build_cross_links(
        self,
        subjects: List[Dict[str, Any]],
        primary_key: str,
        column_types: List[str],
    ) -> List[Dict[str, Any]]:
        value_to_subjects: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        cross_links: List[Dict[str, Any]] = []

        for subject in subjects:
            subject_id = subject["subject_id"]
            for column_type in column_types:
                label = _label_for_type(column_type)
                values = subject.get(label)
                if not values:
                    continue
                for value in values:
                    value_to_subjects[(column_type, value)].add(subject_id)

        seen_pairs: Set[Tuple[str, str, str]] = set()
        for (linked_type, linked_value), subject_ids in value_to_subjects.items():
            if len(subject_ids) < 2:
                continue
            sorted_ids = sorted(subject_ids)
            for index in range(len(sorted_ids)):
                for other in range(index + 1, len(sorted_ids)):
                    left = sorted_ids[index]
                    right = sorted_ids[other]
                    pair_key = (left, right, linked_value)
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    cross_links.append(
                        {
                            "subject_a": left,
                            "subject_b": right,
                            "shared_type": linked_type,
                            "shared_value": linked_value,
                            "relationship": "shared_identifier",
                        }
                    )

        return cross_links

    def _build_graph(
        self,
        subjects: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
        cross_links: List[Dict[str, Any]],
        primary_key: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        for subject in subjects:
            node_id = f"subject:{subject['subject_id']}"
            nodes[node_id] = {
                "id": node_id,
                "label": subject["primary_value"],
                "type": "subject",
                "primary_type": primary_key,
            }

        for connection in connections:
            linked_value = connection["linked_value"]
            linked_type = connection["linked_type"]
            node_id = f"{linked_type}:{linked_value}"
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": linked_value,
                    "type": "identifier",
                    "identifier_type": linked_type,
                }

            edges.append(
                {
                    "source": f"subject:{connection['subject_id']}",
                    "target": node_id,
                    "relationship": connection["relationship"],
                    "source_case": connection.get("source_case"),
                }
            )

        for link in cross_links:
            edges.append(
                {
                    "source": f"subject:{link['subject_a']}",
                    "target": f"subject:{link['subject_b']}",
                    "relationship": link["relationship"],
                    "shared_type": link["shared_type"],
                    "shared_value": link["shared_value"],
                }
            )

        return list(nodes.values()), edges

    def export_graph_networkx(self, corpus: Dict[str, Any]) -> Optional[Any]:
        """Optional NetworkX graph for programmatic analysis."""
        try:
            import networkx as nx
        except ImportError:
            return None

        graph = nx.Graph()
        for node in corpus.get("graph", {}).get("nodes", []):
            graph.add_node(
                node["id"],
                label=node.get("label"),
                node_type=node.get("type"),
            )
        for edge in corpus.get("graph", {}).get("edges", []):
            graph.add_edge(
                edge["source"],
                edge["target"],
                relationship=edge.get("relationship"),
            )
        return graph

    def export_csv_bundle(self, corpus: Dict[str, Any]) -> bytes:
        buffer = io.StringIO()

        subjects = corpus["subjects"]
        if subjects:
            fieldnames = list(subjects[0].keys())
            writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in subjects:
                writer.writerow(self._csv_row(row))
        else:
            buffer.write("subject_id\n")

        connections_buffer = io.StringIO()
        connections = corpus["connections"]
        if connections:
            conn_fields = list(connections[0].keys())
            conn_writer = csv.DictWriter(
                connections_buffer, fieldnames=conn_fields, extrasaction="ignore"
            )
            conn_writer.writeheader()
            for row in connections:
                conn_writer.writerow(row)

        cross_buffer = io.StringIO()
        cross_links = corpus.get("cross_links", [])
        if cross_links:
            cross_fields = list(cross_links[0].keys())
            cross_writer = csv.DictWriter(
                cross_buffer, fieldnames=cross_fields, extrasaction="ignore"
            )
            cross_writer.writeheader()
            for row in cross_links:
                cross_writer.writerow(row)

        zip_buffer = io.BytesIO()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"subjects_{stamp}.csv", buffer.getvalue())
            archive.writestr(f"connections_{stamp}.csv", connections_buffer.getvalue())
            if cross_links:
                archive.writestr(f"cross_links_{stamp}.csv", cross_buffer.getvalue())
            archive.writestr(
                f"graph_{stamp}.json",
                json.dumps(corpus["graph"], indent=2, ensure_ascii=False),
            )
            archive.writestr(
                f"meta_{stamp}.json",
                json.dumps(corpus["meta"], indent=2, ensure_ascii=False),
            )

        zip_buffer.seek(0)
        return zip_buffer.read()

    def export_excel(self, corpus: Dict[str, Any]) -> bytes:
        try:
            import pandas as pd
        except ImportError as exc:
            raise RuntimeError("pandas is required for Excel export") from exc

        output = io.BytesIO()
        subjects_df = pd.DataFrame([self._flatten_row(row) for row in corpus["subjects"]])
        connections_df = pd.DataFrame(corpus["connections"])
        cross_df = pd.DataFrame(corpus.get("cross_links", []))
        meta_df = pd.DataFrame([corpus["meta"]])

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            subjects_df.to_excel(writer, sheet_name="subjects", index=False)
            connections_df.to_excel(writer, sheet_name="connections", index=False)
            if not cross_df.empty:
                cross_df.to_excel(writer, sheet_name="cross_links", index=False)
            meta_df.to_excel(writer, sheet_name="meta", index=False)

        output.seek(0)
        return output.read()

    def export_json(self, corpus: Dict[str, Any]) -> bytes:
        return json.dumps(corpus, indent=2, ensure_ascii=False).encode("utf-8")

    def _csv_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        flattened = self._flatten_row(row)
        for key, value in flattened.items():
            if value is None:
                flattened[key] = ""
        return flattened

    def _flatten_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        flattened: Dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, list):
                flattened[key] = "; ".join(value) if value else None
            else:
                flattened[key] = value
        return flattened
