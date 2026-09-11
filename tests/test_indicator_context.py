#!/usr/bin/env python3
"""Unit tests for crypto/name regex and context disambiguation policy."""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Public, well-known addresses (not case data).
BTC_GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
ETH_SAMPLE = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
# Classic wiki example used as a URL path lookalike; not treated as a live wallet here.
BTC_URL_CHUNK = "1BoatSLGZe4x9y5r3zarvary0c5xw7kv8f3t4"


class TestIndicatorContext(unittest.TestCase):
    def test_strong_btc_without_keywords_is_kept(self):
        from revelare.core.file_processors import TextFileProcessor

        text = "Reference note: %s appears in the file.\n" % BTC_GENESIS
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertIn(BTC_GENESIS, findings.get("Bitcoin_Addresses", {}))

    def test_strong_eth_and_bech32_without_keywords_are_kept(self):
        from revelare.core.file_processors import TextFileProcessor

        text = "Values: %s and %s\n" % (ETH_SAMPLE, BTC_BECH32)
        findings = TextFileProcessor()._find_matches_in_text(text, "fixture.txt")
        self.assertIn(ETH_SAMPLE, findings.get("Ethereum_Addresses", {}))
        self.assertIn(BTC_BECH32, findings.get("Bitcoin_Addresses", {}))

    def test_url_embedded_lookalike_is_dropped(self):
        from revelare.core.file_processors import TextFileProcessor

        text = (
            "See https://example.com/%s/tx?q=1BoatSLGZe4x9y5r3zarvary0c5xw7kv8f3t4\n"
            "Zoom: https://us05web.zoom.us/j/87683254481?pwd=3Db6XhvUnngnfIvXDXIbkbyepaYcsp9a.1\n"
            % BTC_GENESIS
        )
        findings = TextFileProcessor()._find_matches_in_text(text, "urls.txt")
        btc = findings.get("Bitcoin_Addresses", {})
        self.assertNotIn(BTC_GENESIS, btc)
        self.assertFalse(any(v.startswith("3Db") or v.startswith("1Boat") for v in btc))

    def test_real_btc_kept_when_url_and_standalone_both_present(self):
        from revelare.core.file_processors import TextFileProcessor

        text = (
            "https://explorer.example/%s\n"
            "Separate line with the same wallet: %s\n"
            % (BTC_GENESIS, BTC_GENESIS)
        )
        findings = TextFileProcessor()._find_matches_in_text(text, "mixed.txt")
        self.assertIn(BTC_GENESIS, findings.get("Bitcoin_Addresses", {}))

    def test_ambiguous_base58_needs_context(self):
        from revelare.core.indicator_context import accept_crypto_match

        # Valid Base58 charset/length but not a checksummed address.
        ambiguous = "1xxxxxxxxxxxxxxxxxxxxxxxxx"
        self.assertGreaterEqual(len(ambiguous), 26)
        bare = "Token %s in a log line.\n" % ambiguous
        start = bare.index(ambiguous)
        self.assertFalse(
            accept_crypto_match(
                "Bitcoin_Addresses", ambiguous, bare, start, start + len(ambiguous)
            )
        )
        keyed = "Send btc to wallet %s tonight.\n" % ambiguous
        start = keyed.index(ambiguous)
        self.assertTrue(
            accept_crypto_match(
                "Bitcoin_Addresses", ambiguous, keyed, start, start + len(ambiguous)
            )
        )

    def test_jane_doe_without_keywords_is_kept(self):
        from revelare.core.subject_extractor import extract_subject_names

        names = extract_subject_names("Please interview Jane Doe tomorrow.", "warrant.txt")
        self.assertIn("Jane Doe", names)

    def test_jane_doe_inside_html_paragraph_is_kept(self):
        from revelare.core.subject_extractor import extract_subject_names

        names = extract_subject_names("<p>Please interview Jane Doe tomorrow.</p>", "note.html")
        self.assertIn("Jane Doe", names)

    def test_john_smith_on_warrant_field_is_kept(self):
        from revelare.core.subject_extractor import extract_subject_names

        names = extract_subject_names("Defendant: John Smith\n", "warrant.txt")
        self.assertIn("John Smith", names)

    def test_email_header_names_are_dropped(self):
        from revelare.core.subject_extractor import extract_subject_names

        text = (
            "From: Court Clerk <clerk@example.gov>\n"
            "Subject: Editorial Review\n"
            "Dear Sir,\n"
            "United States\n"
        )
        names = extract_subject_names(text, "mail.eml")
        self.assertNotIn("Court Clerk", names)
        self.assertNotIn("Editorial Review", names)
        self.assertNotIn("Dear Sir", names)
        self.assertNotIn("United States", names)

    def test_form_label_phrases_dropped_real_names_kept(self):
        from revelare.core.indicator_context import is_blocked_name_phrase
        from revelare.core.subject_extractor import extract_subject_names

        drops = (
            "Emergency Response",
            "Case No",
            "Start Date End",
            "Coordinated Universal Time",
            "Search Warrant",
            "Call Detail Records",
            "Tower Address",
            "Start Date",
            "End Date",
            "Subscriber Name",
            "Billing Address",
            "First Name",
        )
        for phrase in drops:
            self.assertTrue(is_blocked_name_phrase(phrase), phrase)
        self.assertFalse(is_blocked_name_phrase("Jane Doe"))
        self.assertFalse(is_blocked_name_phrase("Martin Brown"))
        self.assertFalse(is_blocked_name_phrase("Markus Johnson"))

        text = "\n".join(
            list(drops)
            + [
                "Please interview Jane Doe tomorrow.",
                "Please interview Martin Brown tomorrow.",
            ]
        )
        names = extract_subject_names(text, "labels.txt")
        for phrase in drops:
            self.assertNotIn(phrase, names)
        self.assertIn("Jane Doe", names)
        self.assertIn("Martin Brown", names)

    def test_two_token_shape_keeps_initial_drops_word_strings(self):
        from revelare.core.indicator_context import is_blocked_name_phrase
        from revelare.core.subject_extractor import extract_subject_names
        from revelare.core.validators import DataValidator

        self.assertTrue(DataValidator.is_valid_person_name("Mary A. Smith"))
        self.assertTrue(DataValidator.is_valid_person_name("Markus Johnson"))
        self.assertTrue(DataValidator.is_valid_person_name("Jane Doe Jr"))
        self.assertFalse(DataValidator.is_valid_person_name("Call Detail Records"))
        self.assertFalse(DataValidator.is_valid_person_name("Date Time Duration"))
        self.assertFalse(is_blocked_name_phrase("Mary A. Smith"))
        self.assertFalse(is_blocked_name_phrase("Markus Johnson"))

        text = (
            "Please interview Jane Doe tomorrow.\n"
            "Please interview Martin Brown tomorrow.\n"
            "Please interview Markus Johnson tomorrow.\n"
            "Signed Mary A. Smith on the form.\n"
            "Call Detail Records\n"
            "Date Time Duration\n"
            "Emergency Response\n"
            "Start Date End\n"
            "Identifier Requested Item\n"
            "Grief Etiquette Editorial\n"
        )
        names = extract_subject_names(text, "shape.txt")
        self.assertIn("Jane Doe", names)
        self.assertIn("Martin Brown", names)
        self.assertIn("Markus Johnson", names)
        self.assertIn("Mary A. Smith", names)
        self.assertNotIn("Call Detail Records", names)
        self.assertNotIn("Call Detail", names)
        self.assertNotIn("Detail Records", names)
        self.assertNotIn("Date Time Duration", names)
        self.assertNotIn("Date Time", names)
        self.assertNotIn("Time Duration", names)
        self.assertNotIn("Emergency Response", names)
        self.assertNotIn("Start Date End", names)
        self.assertNotIn("Identifier Requested Item", names)
        self.assertNotIn("Grief Etiquette Editorial", names)
        self.assertNotIn("Grief Etiquette", names)
        self.assertNotIn("Our Pre", names)
        self.assertNotIn("Launch Package", names)
        self.assertNotIn("Order Reminders", names)

    def test_hyphenated_titles_are_not_sliced(self):
        from revelare.core.subject_extractor import extract_subject_names

        text = (
            "Our Pre-Launch Package\n"
            "Pre-Order Reminders\n"
            "Please interview Jane Doe tomorrow.\n"
        )
        names = extract_subject_names(text, "hyphen.txt")
        self.assertIn("Jane Doe", names)
        self.assertNotIn("Our Pre", names)
        self.assertNotIn("Pre Launch", names)
        self.assertNotIn("Launch Package", names)
        self.assertNotIn("Order Reminders", names)
        self.assertNotIn("Pre Order", names)

    def test_role_prefix_and_greeting_are_dropped(self):
        from revelare.core.subject_extractor import extract_subject_names

        text = (
            "Inv M. Johnson prepared the cover sheet.\n"
            "Hi Tyra, this greeting is not a subject name.\n"
            "Please interview Jane Doe tomorrow.\n"
        )
        names = extract_subject_names(text, "role.txt")
        self.assertIn("Jane Doe", names)
        self.assertNotIn("Inv M. Johnson", names)
        self.assertNotIn("Hi Tyra", names)

    def test_synthetic_known_name_benchmark(self):
        import importlib.util

        from revelare.core.subject_extractor import extract_subject_names

        gen_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "generate_synthetic_name_docs.py"
        )
        spec = importlib.util.spec_from_file_location("generate_synthetic_name_docs", gen_path)
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)

        gen.write_documents(gen.default_out_dir())
        extracted = []
        for file_name, text in gen.all_documents().items():
            extracted.extend(extract_subject_names(text, file_name).keys())
        report = gen.score_names(extracted)
        self.assertEqual(report["false_negatives"], [], report)
        self.assertEqual(report["false_positives"], [], report)
        self.assertEqual(report["recall"], 1.0, report)
        self.assertEqual(report["precision"], 1.0, report)
        self.assertEqual(report["known_count"], 8)
        names = set(extracted)
        for known in gen.KNOWN_NAMES:
            self.assertIn(known, names)
        for phrase in gen.JUNK_PHRASES:
            self.assertNotIn(phrase, names)

    def test_end_to_end_fixture_counts(self):
        from revelare.core.file_processors import TextFileProcessor

        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "crypto_name_fp.txt")
        with open(fixture, "r", encoding="ascii") as handle:
            text = handle.read()
        findings = TextFileProcessor()._find_matches_in_text(text, "crypto_name_fp.txt")
        btc = set(findings.get("Bitcoin_Addresses", {}))
        eth = set(findings.get("Ethereum_Addresses", {}))
        names = set(findings.get("Subject_Names", {}))
        self.assertIn(BTC_GENESIS, btc)
        self.assertIn(BTC_BECH32, btc)
        self.assertIn(ETH_SAMPLE, eth)
        self.assertNotIn(BTC_URL_CHUNK, btc)
        self.assertIn("Jane Doe", names)
        self.assertIn("Martin Brown", names)
        self.assertIn("Markus Johnson", names)
        self.assertIn("Mary A. Smith", names)
        self.assertIn("John Smith", names)
        self.assertNotIn("Court Clerk", names)
        self.assertNotIn("Editorial Review", names)
        self.assertNotIn("Emergency Response", names)
        self.assertNotIn("Case No", names)
        self.assertNotIn("Start Date End", names)
        self.assertNotIn("Coordinated Universal Time", names)
        self.assertNotIn("Call Detail Records", names)
        self.assertNotIn("Call Detail", names)
        self.assertNotIn("Date Time Duration", names)
        self.assertNotIn("Identifier Requested Item", names)


class TestStrongCryptoHelpers(unittest.TestCase):
    def test_genesis_is_base58check(self):
        from revelare.core.indicator_context import is_strong_bitcoin

        self.assertTrue(is_strong_bitcoin(BTC_GENESIS))
        self.assertTrue(is_strong_bitcoin(BTC_BECH32))
        self.assertFalse(is_strong_bitcoin("1xxxxxxxxxxxxxxxxxxxxxxxxx"))

    def test_patterns_compile(self):
        from revelare.core.indicator_context import compiled_regex_patterns

        compiled = compiled_regex_patterns()
        self.assertIn("Bitcoin_Addresses", compiled)
        self.assertTrue(compiled["Bitcoin_Addresses"].fullmatch(BTC_GENESIS))
        self.assertTrue(compiled["Ethereum_Addresses"].fullmatch(ETH_SAMPLE))


BTC_IN_IMAGE = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


def _synthetic_email_with_image():
    # Base64 blob with coincidental Base58 runs plus a real checksummed address
    # that must NOT be reported when it only appears inside the image part.
    blob_lines = [
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEB",
        "AQEBAQEBAQEBAQEBAQEBAAAAAAAAAAAAAAAAAAAAAAAA",
        BTC_IN_IMAGE,
        "1xxxxxxxxxxxxxxxxxxxxxxxxxQQQQQQQQQQQQQQQQQQ",
        "3M4IaL0sBQfb8T7Qqv3kTVb6caNlXXXXXXXXXXXXXXXX",
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4",
        "nGMAAQAABQABDQottAAAAABJRU5ErkJggg==",
    ]
    blob = "\n".join(blob_lines * 8)
    return (
        "MIME-Version: 1.0\n"
        "From: sender@example.com\n"
        "To: analyst@example.gov\n"
        "Subject: Payment instructions\n"
        "Content-Type: multipart/related; boundary=\"----=_Part_7_IMG\"\n"
        "\n"
        "------=_Part_7_IMG\n"
        "Content-Type: text/plain; charset=\"utf-8\"\n"
        "\n"
        "Please use this wallet: %s\n"
        "Also interview Jane Doe tomorrow.\n"
        "\n"
        "------=_Part_7_IMG\n"
        "Content-Type: image/jpeg; name=\"photo.jpg\"\n"
        "Content-Transfer-Encoding: base64\n"
        "Content-Disposition: inline; filename=\"photo.jpg\"\n"
        "Content-ID: <photo.jpg@example.com>\n"
        "\n"
        "%s\n"
        "------=_Part_7_IMG\n"
        "Content-Type: application/octet-stream; name=\"inline.png\"\n"
        "Content-Transfer-Encoding: base64\n"
        "Content-Disposition: attachment; filename=\"inline.png\"\n"
        "Content-ID: <inline.png@example.com>\n"
        "\n"
        "%s\n"
        "------=_Part_7_IMG--\n"
        "\n"
        "<img src=\"cid:photo.jpg@example.com\">\n"
        % (BTC_GENESIS, blob, blob)
    )


class TestMimeImageSkip(unittest.TestCase):
    def test_image_part_wallets_dropped_text_wallet_kept(self):
        from revelare.core.file_processors import TextFileProcessor
        from revelare.core.indicator_context import is_strong_bitcoin

        self.assertTrue(is_strong_bitcoin(BTC_IN_IMAGE))
        eml = _synthetic_email_with_image()
        findings = TextFileProcessor()._find_matches_in_text(eml, "synthetic.eml")
        btc = set(findings.get("Bitcoin_Addresses", {}))
        names = set(findings.get("Subject_Names", {}))
        self.assertIn(BTC_GENESIS, btc)
        self.assertNotIn(BTC_IN_IMAGE, btc)
        self.assertFalse(any(v.startswith("1xxxx") or v.startswith("3M4I") for v in btc))
        self.assertEqual(btc, {BTC_GENESIS})
        self.assertIn("Jane Doe", names)

    def test_fixture_eml_skips_image_payload(self):
        import os
        from revelare.core.file_processors import TextFileProcessor

        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "image_btc.eml")
        with open(fixture, "r", encoding="ascii") as handle:
            text = handle.read()
        findings = TextFileProcessor()._find_matches_in_text(text, "image_btc.eml")
        btc = set(findings.get("Bitcoin_Addresses", {}))
        self.assertIn(BTC_GENESIS, btc)
        self.assertNotIn(BTC_IN_IMAGE, btc)

    def test_email_processor_uses_mime_skip(self):
        import os
        import tempfile
        from revelare.core.file_processors import EmailFileProcessor

        eml = _synthetic_email_with_image()
        tmp = tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False, encoding="ascii")
        try:
            tmp.write(eml)
            tmp.close()
            findings = EmailFileProcessor().process_file(tmp.name, os.path.basename(tmp.name))
        finally:
            os.unlink(tmp.name)
        btc = set(findings.get("Bitcoin_Addresses", {}))
        self.assertIn(BTC_GENESIS, btc)
        self.assertNotIn(BTC_IN_IMAGE, btc)

    def test_html_data_uri_image_is_masked(self):
        from revelare.core.file_processors import TextFileProcessor

        html = (
            "<html><body>Pay %s"
            "<img src=\"data:image/png;base64,AAAA%sBBBB\"/>"
            "</body></html>\n"
            % (BTC_GENESIS, BTC_IN_IMAGE)
        )
        findings = TextFileProcessor()._find_matches_in_text(html, "mail.html")
        btc = set(findings.get("Bitcoin_Addresses", {}))
        self.assertIn(BTC_GENESIS, btc)
        self.assertNotIn(BTC_IN_IMAGE, btc)


if __name__ == "__main__":
    unittest.main()
