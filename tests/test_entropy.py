import unittest
from envshield.entropy import is_high_entropy, shannon_entropy


class TestEntropy(unittest.TestCase):
    def test_shannon_entropy_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_shannon_entropy_uniform_repetition(self):
        # A single repeated character has 0 entropy
        self.assertEqual(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0)

    def test_shannon_entropy_random_string(self):
        # Typical base64 high-entropy random key
        secret = "c2VjcmV0LWtleS0xMjM0NTY3ODkwLXJhbmRvbQ=="
        entropy = shannon_entropy(secret)
        self.assertGreater(entropy, 4.0)

    def test_is_high_entropy_short_string(self):
        self.assertFalse(is_high_entropy("abc"))

    def test_is_high_entropy_whitespace(self):
        self.assertFalse(is_high_entropy("this is a normal human readable sentence"))

    def test_is_high_entropy_true_positive(self):
        token = "9f8e7d6c5b4a3928170e1d2c3b4a5968"
        self.assertTrue(is_high_entropy(token, threshold=3.5))


if __name__ == "__main__":
    unittest.main()
