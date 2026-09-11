"""
Flat-row corpus export for bond-scam / gov-impersonation subject linkage.

Produces one row per identifier with subject grouping via a chosen primary key.
Unknown or missing fields are exported as null/empty.
"""
import csv
import io
import json
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from revelare.core.context_parser import contexts_share_segment, parse_context_fields
from revelare.utils.corpus_builder import (
    COLUMN_LABELS,
    DEFAULT_COLUMN_TYPES,
    PRIMARY_CASE,
    CorpusBuilder,
    _label_for_type,
)
from revelare.utils.logger import get_logger

logger = get_logger(__name__)

FLAT_COLUMNS = [
    "subject_id",
    "primary_identifier",
    "subject_role",
    "identifier_type",
    "identifier_value",
    "source_case",
    "source_file",
    "account_segment",
    "segment_anchor",
    "multi_account_risk",
    "context",
    "linked_to",
]


def _parse_source_file(context: Optional[str]) -> Optional[str]:
    fields = parse_context_fields(context)
    return fields.get("file")


def _flat_fields_from_context(context: Optional[str]) -> Dict[str, Optional[str]]:
    fields = parse_context_fields(context)
    return {
        "subject_role": fields.get("role"),
        "account_segment": fields.get("segment"),
        "segment_anchor": fields.get("segmentanchor"),
        "multi_account_risk": fields.get("multiaccountrisk"),
        "source_file": fields.get("file"),
    }


def _join_linked(values: Set[str]) -> Optional[str]:
    if not values:
        return None
    return "; ".join(sorted(values))


class CorpusExporter:
    """Export subject-linked identifier rows in flat CSV/Excel format."""

    def __init__(
        self,
        cases_dir: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        self.builder = CorpusBuilder(cases_dir=cases_dir, db_path=db_path)

    def discover_cases(self) -> List[Dict[str, Any]]:
        return self.builder.discover_cases()

    def get_available_identifier_types(
        self, case_names: Optional[List[str]] = None
    ) -> List[str]:
        return self.builder.get_available_identifier_types(case_names)

    def build_flat_rows(
        self,
        case_names: List[str],
        primary_key: str,
        column_types: List[str],
    ) -> List[Dict[str, Any]]:
        if not case_names:
            raise ValueError("Select at least one case.")

        if not column_types:
            column_types = [
                t
                for t in self.builder.get_available_identifier_types(case_names)
                if t != PRIMARY_CASE
            ]

        case_data = self.builder.load_case_indicators(case_names)
        rows: List[Dict[str, Any]] = []

        for case_name, categories in sorted(case_data.items()):
            if primary_key == PRIMARY_CASE:
                rows.extend(
                    self._rows_for_subject(
                        subject_id=case_name,
                        primary_identifier=case_name,
                        case_name=case_name,
                        categories=categories,
                        column_types=column_types,
                        primary_key=primary_key,
                    )
                )
                continue

            primary_values = list(categories.get(primary_key, {}).keys())
            if not primary_values:
                continue

            for primary_value in primary_values:
                primary_context = categories.get(primary_key, {}).get(primary_value, "")
                linked_for_subject = self._collect_case_values(
                    categories,
                    column_types,
                    exclude_type=primary_key,
                    reference_context=primary_context,
                )
                linked_for_subject.discard(primary_value)
                rows.extend(
                    self._rows_for_subject(
                        subject_id=primary_value,
                        primary_identifier=primary_value,
                        case_name=case_name,
                        categories=categories,
                        column_types=column_types,
                        primary_key=primary_key,
                        fixed_linked=linked_for_subject,
                    )
                )

        return rows

    def _collect_case_values(
        self,
        categories: Dict[str, Dict[str, str]],
        column_types: List[str],
        exclude_type: Optional[str] = None,
        reference_context: Optional[str] = None,
    ) -> Set[str]:
        values: Set[str] = set()
        for column_type in column_types:
            if column_type == exclude_type:
                continue
            for value, context in categories.get(column_type, {}).items():
                if reference_context and not contexts_share_segment(reference_context, context):
                    continue
                values.add(value)
        return values

    def _linked_values_for_context(
        self,
        categories: Dict[str, Dict[str, str]],
        column_types: List[str],
        primary_key: str,
        value: str,
        context: Optional[str],
        fixed_linked: Optional[Set[str]] = None,
    ) -> Set[str]:
        if fixed_linked is not None:
            linked = set(fixed_linked)
            linked.discard(value)
            return linked

        linked: Set[str] = set()
        for column_type in column_types:
            if column_type == primary_key:
                continue
            for other_value, other_context in categories.get(column_type, {}).items():
                if other_value == value:
                    continue
                if contexts_share_segment(context, other_context):
                    linked.add(other_value)
        return linked

    def _make_flat_row(
        self,
        subject_id: str,
        primary_identifier: str,
        column_type: str,
        value: str,
        case_name: str,
        context: Optional[str],
        linked: Set[str],
    ) -> Dict[str, Any]:
        ctx_fields = _flat_fields_from_context(context)
        return {
            "subject_id": subject_id,
            "primary_identifier": primary_identifier,
            "subject_role": ctx_fields.get("subject_role"),
            "identifier_type": _label_for_type(column_type),
            "identifier_value": value,
            "source_case": case_name,
            "source_file": ctx_fields.get("source_file"),
            "account_segment": ctx_fields.get("account_segment"),
            "segment_anchor": ctx_fields.get("segment_anchor"),
            "multi_account_risk": ctx_fields.get("multi_account_risk"),
            "context": context if context else None,
            "linked_to": _join_linked(linked),
        }

    def _rows_for_subject(
        self,
        subject_id: str,
        primary_identifier: str,
        case_name: str,
        categories: Dict[str, Dict[str, str]],
        column_types: List[str],
        primary_key: str,
        fixed_linked: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []

        for column_type in column_types:
            if column_type == primary_key:
                continue
            items = categories.get(column_type, {})
            for value, context in items.items():
                linked = self._linked_values_for_context(
                    categories,
                    column_types,
                    primary_key,
                    value,
                    context,
                    fixed_linked=fixed_linked,
                )
                rows.append(
                    self._make_flat_row(
                        subject_id,
                        primary_identifier,
                        column_type,
                        value,
                        case_name,
                        context,
                        linked,
                    )
                )

        if primary_key != PRIMARY_CASE and primary_identifier in categories.get(
            primary_key, {}
        ):
            context = categories[primary_key][primary_identifier]
            linked = self._linked_values_for_context(
                categories,
                column_types,
                primary_key,
                primary_identifier,
                context,
                fixed_linked=fixed_linked,
            )
            rows.insert(
                0,
                self._make_flat_row(
                    subject_id,
                    primary_identifier,
                    primary_key,
                    primary_identifier,
                    case_name,
                    context,
                    linked,
                ),
            )

        return rows

    def build_export_bundle(
        self,
        case_names: List[str],
        primary_key: str,
        column_types: List[str],
        include_cross_links: bool = True,
    ) -> Dict[str, Any]:
        flat_rows = self.build_flat_rows(case_names, primary_key, column_types)
        corpus = self.builder.build_corpus(
            case_names=case_names,
            primary_key=primary_key,
            column_types=column_types,
            include_cross_links=include_cross_links,
        )
        corpus["flat_rows"] = flat_rows
        corpus["meta"]["flat_row_count"] = len(flat_rows)
        return corpus

    def export_csv(self, rows: List[Dict[str, Any]]) -> bytes:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=FLAT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(self._null_safe_row(row))
        return buffer.getvalue().encode("utf-8")

    def export_csv_bundle(self, corpus: Dict[str, Any]) -> bytes:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        flat_csv = self.export_csv(corpus.get("flat_rows", []))

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"identifiers_{stamp}.csv", flat_csv)
            archive.writestr(
                f"subjects_{stamp}.csv",
                self._subjects_csv(corpus.get("subjects", [])),
            )
            archive.writestr(
                f"connections_{stamp}.csv",
                self._connections_csv(corpus.get("connections", [])),
            )
            cross_links = corpus.get("cross_links", [])
            if cross_links:
                archive.writestr(
                    f"cross_links_{stamp}.csv",
                    self._generic_csv(cross_links),
                )
            archive.writestr(
                f"meta_{stamp}.json",
                json.dumps(corpus.get("meta", {}), indent=2, ensure_ascii=False),
            )
            if corpus.get("graph"):
                archive.writestr(
                    f"graph_{stamp}.json",
                    json.dumps(corpus["graph"], indent=2, ensure_ascii=False),
                )

        zip_buffer.seek(0)
        return zip_buffer.read()

    def export_excel(self, corpus: Dict[str, Any]) -> bytes:
        try:
            import pandas as pd
        except ImportError as exc:
            raise RuntimeError("pandas is required for Excel export") from exc

        output = io.BytesIO()
        flat_df = pd.DataFrame(
            [self._null_safe_row(row) for row in corpus.get("flat_rows", [])]
        )
        subjects_df = pd.DataFrame(
            [self.builder._flatten_row(row) for row in corpus.get("subjects", [])]
        )
        connections_df = pd.DataFrame(corpus.get("connections", []))
        cross_df = pd.DataFrame(corpus.get("cross_links", []))
        meta_df = pd.DataFrame([corpus.get("meta", {})])

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            if not flat_df.empty:
                flat_df.to_excel(writer, sheet_name="identifiers", index=False)
            else:
                pd.DataFrame(columns=FLAT_COLUMNS).to_excel(
                    writer, sheet_name="identifiers", index=False
                )
            if not subjects_df.empty:
                subjects_df.to_excel(writer, sheet_name="subjects", index=False)
            if not connections_df.empty:
                connections_df.to_excel(writer, sheet_name="connections", index=False)
            if not cross_df.empty:
                cross_df.to_excel(writer, sheet_name="cross_links", index=False)
            meta_df.to_excel(writer, sheet_name="meta", index=False)

        output.seek(0)
        return output.read()

    def export_json(self, corpus: Dict[str, Any]) -> bytes:
        payload = {
            "meta": corpus.get("meta", {}),
            "flat_rows": corpus.get("flat_rows", []),
            "subjects": corpus.get("subjects", []),
            "connections": corpus.get("connections", []),
            "cross_links": corpus.get("cross_links", []),
            "graph": corpus.get("graph", {}),
        }
        return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

    def _null_safe_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}
        for key in FLAT_COLUMNS:
            value = row.get(key)
            cleaned[key] = "" if value is None else value
        return cleaned

    def _subjects_csv(self, subjects: List[Dict[str, Any]]) -> str:
        if not subjects:
            return "subject_id\n"
        buffer = io.StringIO()
        fieldnames = list(subjects[0].keys())
        writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in subjects:
            writer.writerow(self.builder._csv_row(row))
        return buffer.getvalue()

    def _connections_csv(self, connections: List[Dict[str, Any]]) -> str:
        if not connections:
            return "subject_id\n"
        return self._generic_csv(connections)

    def _generic_csv(self, rows: List[Dict[str, Any]]) -> str:
        buffer = io.StringIO()
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return buffer.getvalue()


__all__ = [
    "CorpusExporter",
    "FLAT_COLUMNS",
    "PRIMARY_CASE",
    "DEFAULT_COLUMN_TYPES",
    "COLUMN_LABELS",
]
