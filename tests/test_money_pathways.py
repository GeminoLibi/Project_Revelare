#!/usr/bin/env python3
"""Unit tests for bank/fintech/gambling pathway detectors and link policy."""
import json
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestMoneyPathways(unittest.TestCase):
    def test_cash_app_cashtag_is_pathway_plus_linkable_token(self):
        from revelare.core.file_processors import TextFileProcessor

        text = "sent $50 via Cash App $victimname\n"
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertIn("Cash App", findings.get("Fintech_Apps", {}))
        tokens = findings.get("Payment_Tokens", {})
        self.assertIn("$victimname", tokens)
        self.assertNotIn("$50", tokens)

    def test_paypal_alone_is_pathway_not_link_node(self):
        from revelare.core.file_processors import TextFileProcessor
        from revelare.core.money_pathways import (
            LINK_ANALYSIS_CATEGORIES,
            PATHWAY_CATEGORIES,
            is_link_analysis_category,
        )

        text = "Please refund me on PayPal\n"
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertIn("PayPal", findings.get("Fintech_Apps", {}))
        self.assertFalse(findings.get("Payment_Tokens"))
        self.assertIn("Fintech_Apps", PATHWAY_CATEGORIES)
        self.assertNotIn("Fintech_Apps", LINK_ANALYSIS_CATEGORIES)
        self.assertFalse(is_link_analysis_category("Fintech_Apps"))
        self.assertFalse(is_link_analysis_category("Financial_Institutions"))
        self.assertFalse(is_link_analysis_category("Gambling_Sites"))
        self.assertTrue(is_link_analysis_category("Payment_Tokens"))

    def test_purchase_is_not_chase(self):
        from revelare.core.file_processors import TextFileProcessor

        text = "The purchase was completed yesterday.\n"
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertNotIn("Chase", findings.get("Financial_Institutions", {}))
        self.assertFalse(findings.get("Financial_Institutions"))

    def test_chase_bank_and_draftkings_are_pathways(self):
        from revelare.core.file_processors import TextFileProcessor

        text = "Wired from Chase acct 123456789 to DraftKings user @dkplayer\n"
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertIn("Chase", findings.get("Financial_Institutions", {}))
        self.assertIn("DraftKings", findings.get("Gambling_Sites", {}))
        tokens = findings.get("Payment_Tokens", {})
        self.assertIn("123456789", tokens)
        self.assertIn("@dkplayer", tokens)

    def test_link_analysis_graph_skips_brands_keeps_tokens(self):
        from revelare.core.link_analysis import LinkAnalysisService

        td = tempfile.mkdtemp(prefix="revelare_pathways_la_")
        try:
            case_a = os.path.join(td, "cases", "CaseA")
            case_b = os.path.join(td, "cases", "CaseB")
            os.makedirs(case_a, exist_ok=True)
            os.makedirs(case_b, exist_ok=True)
            with open(os.path.join(case_a, "indicators.json"), "w", encoding="ascii") as handle:
                json.dump(
                    {
                        "Fintech_Apps": {"PayPal": "File: a.txt"},
                        "Payment_Tokens": {"$victimname": "File: a.txt | Type: Cashtag"},
                        "Email_Addresses": {"a@example.com": "File: a.txt"},
                    },
                    handle,
                )
            with open(os.path.join(case_b, "indicators.json"), "w", encoding="ascii") as handle:
                json.dump(
                    {
                        "Fintech_Apps": {"PayPal": "File: b.txt"},
                        "Payment_Tokens": {"$victimname": "File: b.txt | Type: Cashtag"},
                    },
                    handle,
                )
            service = LinkAnalysisService(os.path.join(td, "cases"))
            self.assertFalse(service.graph.has_node("PayPal"))
            self.assertTrue(service.graph.has_node("$victimname"))
            bridges = service.get_common_links()
            bridge_vals = {row["indicator"] for row in bridges}
            self.assertIn("$victimname", bridge_vals)
            self.assertNotIn("PayPal", bridge_vals)
        finally:
            import shutil
            shutil.rmtree(td, ignore_errors=True)

    def test_wordlist_is_reasonable_us_size(self):
        from revelare.core.money_pathways import wordlist_counts

        counts = wordlist_counts()
        self.assertGreaterEqual(counts["Financial_Institutions"], 30)
        self.assertLessEqual(counts["Financial_Institutions"], 80)
        self.assertGreaterEqual(counts["Fintech_Apps"], 25)
        self.assertLessEqual(counts["Fintech_Apps"], 80)
        self.assertGreaterEqual(counts["Gambling_Sites"], 25)
        self.assertLessEqual(counts["Gambling_Sites"], 80)


if __name__ == "__main__":
    unittest.main()
