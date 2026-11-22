import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditor import analyse, audit, char_pool, crack_times, has_sequence, memo  # noqa: E402


class TestAnalyse(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        r = analyse("password")
        self.assertEqual(r.rating, "Very weak")
        self.assertTrue(any("common-password" in i for i in r.issues))

    def test_decorated_common_word_caught(self):
        self.assertTrue(any("common word" in i for i in analyse("Summer2024!").issues))
        self.assertTrue(any("common word" in i for i in analyse("P@ssw0rd").issues))

    def test_long_passphrase_is_strong(self):
        r = analyse("my dog eats toast on tuesdays")
        self.assertIn(r.rating, ("Strong", "Very strong"))

    def test_sequences(self):
        self.assertTrue(has_sequence("xxqwerxx"))
        self.assertTrue(has_sequence("9876"))
        self.assertFalse(has_sequence("q1w2e3"))

    def test_year_flagged(self):
        self.assertTrue(any("year" in i for i in analyse("Welcome2026").issues))

    def test_pool(self):
        self.assertEqual(char_pool("abc"), 26)
        self.assertEqual(char_pool("aB1!"), 95)
        self.assertEqual(char_pool(""), 0)

    def test_masking_never_shows_whole_password(self):
        self.assertEqual(analyse("secret123").masked, "s*******3")

    def test_slow_hash_takes_longer_to_crack(self):
        times = crack_times(40)
        self.assertNotEqual(times["md5 (unsalted, fast)"], times["bcrypt, cost 12"])


class TestAudit(unittest.TestCase):
    def test_audit_and_memo(self):
        result = audit(["password", "correct horse battery staple", "", "abcd1234"])
        self.assertEqual(result["total"], 3)
        text = memo(result)
        self.assertIn("Recommended controls", text)
        self.assertIn("of 3 passwords", text)


if __name__ == "__main__":
    unittest.main()
