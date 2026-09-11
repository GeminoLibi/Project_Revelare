#!/usr/bin/env python3
"""Emit synthetic warrant/email/CDR text with a FIXED person-name list.

Not case data. Used to benchmark Subject_Names precision/recall.
Run: python tests/fixtures/generate_synthetic_name_docs.py
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

# Eight known people. Extractor must find all of these.
KNOWN_NAMES: List[str] = [
    "Jane Doe",
    "Martin Brown",
    "Markus Johnson",
    "Mary A. Smith",
    "John Smith",
    "Robert Chen",
    "Elena Vasquez",
    "Patricia Williams",
]

# Title-case junk that must not count as people.
JUNK_PHRASES: List[str] = [
    "Case No",
    "Emergency Response",
    "Call Detail Records",
    "Coordinated Universal Time",
    "Search Warrant",
    "Start Date",
    "End Date",
    "Tower Address",
    "Billing Address",
    "Subscriber Name",
    "First Name",
    "Start Date End",
    "Date Time Duration",
    "Identifier Requested Item",
    "Grief Etiquette Editorial",
    "Probable Cause",
    "Daisy Chaining",
    "Linked Accounts",
    "Recovery Methods",
    "Alternative Methods",
    "Sinch Voice",
    "Ported Details",
    "Bill Cycle",
    "Rate Description",
    "Disconnect Reason",
    "Creative Head",
    "Marketing Campaign",
    "Pre-Launch Package",
    "Our Pre-Launch Package",
    "Goodreads Author",
    "Coming Soon",
    "Scenes Graphics",
    "Cover Reveal",
    "Inspirational Messages",
    "Reader Questions",
    "Discussion Topics",
    "Countdown Campaign",
    "Pre-Order Reminders",
    "Keyword Research",
    "Grief Recovery",
    "Child Loss",
    "Emotional Wellness",
    "Trauma Recovery",
    "Campaign Goals",
    "Research Triangle",
    "Social Me",
    "Author You",
    "Hashtag Keyword",
    "Lulu Publishing",
    "Ingram Sparks",
    "Editorial Review",
    "Court Clerk",
    "Dear Sir",
    "United States",
    "Hi Tyra",
    "Inv M. Johnson",
]


def warrant_text() -> str:
    junk_block = "\n".join(JUNK_PHRASES[:16])
    return (
        "SEARCH WARRANT\n"
        "Case No: 26-0001\n"
        "Search Warrant\n"
        "Emergency Response\n"
        "Call Detail Records\n"
        "Coordinated Universal Time: 12:00:00\n"
        "Start Date: 2026-01-01\n"
        "End Date: 2026-03-01\n"
        "Tower Address: 100 Example Rd\n"
        "\n"
        "Subject Name: Jane Doe\n"
        "Defendant: John Smith\n"
        "Target Name: Martin Brown\n"
        "\n"
        "The court authorizes collection of records for Jane Doe.\n"
        "Please interview Martin Brown tomorrow.\n"
        "Please interview Markus Johnson tomorrow.\n"
        "Signed Mary A. Smith on the form.\n"
        "\n"
        f"{junk_block}\n"
    )


def email_text() -> str:
    return (
        "From: Court Clerk <clerk@example.gov>\n"
        "To: analyst@example.gov\n"
        "Subject: Editorial Review\n"
        "Date: Fri, 11 Sep 2026 12:00:00 -0400\n"
        "\n"
        "Dear Sir,\n"
        "United States\n"
        "\n"
        "Coming Soon\n"
        "Cover Reveal\n"
        "Grief Recovery\n"
        "Child Loss\n"
        "Keyword Research\n"
        "Our Pre-Launch Package\n"
        "Pre-Order Reminders\n"
        "Goodreads Author\n"
        "Lulu Publishing\n"
        "Ingram Sparks\n"
        "\n"
        "Please contact Elena Vasquez regarding the manuscript.\n"
        "Please contact Patricia Williams if you have questions.\n"
        "Hi Tyra, this greeting is not a subject name.\n"
        "Inv M. Johnson prepared the cover sheet.\n"
        "\n"
        "Thank you.\n"
    )


def spreadsheet_text() -> str:
    header = (
        "Case No\tStart Date\tEnd Date\tCall Detail Records\t"
        "Disconnect Reason\tBill Cycle\tRate Description\tPorted Details\n"
    )
    row = "26-0001\t2026-01-01\t2026-03-01\tn/a\tCustomer Request\tMonthly\tStandard\tNo\n"
    junk = "\n".join(JUNK_PHRASES[16:])
    return (
        header
        + row
        + "\n"
        "Account Holder: Robert Chen\n"
        "Full Name: Robert Chen\n"
        "\n"
        f"{junk}\n"
        "Creative Head\n"
        "Marketing Campaign\n"
        "Hashtag Keyword\n"
        "Author You\n"
        "Social Me\n"
        "Research Triangle\n"
        "Sinch Voice\n"
        "Daisy Chaining\n"
        "Probable Cause\n"
    )


def all_documents() -> Dict[str, str]:
    return {
        "synthetic_warrant.txt": warrant_text(),
        "synthetic_email.eml": email_text(),
        "synthetic_cdr.txt": spreadsheet_text(),
    }


def write_documents(out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    for name, text in all_documents().items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="ascii", newline="\n") as handle:
            handle.write(text)
        written.append(path)
    meta = {
        "known_names": KNOWN_NAMES,
        "junk_phrases": JUNK_PHRASES,
        "known_count": len(KNOWN_NAMES),
    }
    meta_path = os.path.join(out_dir, "known_names.json")
    with open(meta_path, "w", encoding="ascii", newline="\n") as handle:
        json.dump(meta, handle, indent=2)
        handle.write("\n")
    written.append(meta_path)
    return written


def score_names(extracted: List[str]) -> Dict[str, object]:
    got = set(extracted)
    known = set(KNOWN_NAMES)
    tp = sorted(got & known)
    fn = sorted(known - got)
    fp = sorted(got - known)
    precision = (len(tp) / len(got)) if got else 1.0
    recall = (len(tp) / len(known)) if known else 1.0
    return {
        "known_count": len(known),
        "extracted_count": len(got),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def default_out_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_name_cases")


if __name__ == "__main__":
    paths = write_documents(default_out_dir())
    print("Wrote %d files to %s" % (len(paths), default_out_dir()))
    for path in paths:
        print(" ", path)
