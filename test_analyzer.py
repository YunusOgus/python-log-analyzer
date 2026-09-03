import unittest

from analyzer import analyze_lines


class AnalyzeLinesTests(unittest.TestCase):
    def test_counts_failed_logins_by_ip_and_user(self) -> None:
        lines = [
            "Failed password for invalid user admin from 198.51.100.42 port 1 ssh2\n",
            "Failed password for root from 198.51.100.42 port 2 ssh2\n",
            "Failed password for guest from 203.0.113.8 port 3 ssh2\n",
            "webapp: ERROR unable to connect to test database\n",
        ]

        result = analyze_lines(lines)

        self.assertEqual(result.total_lines, 4)
        self.assertEqual(result.failed_auth_attempts, 3)
        self.assertEqual(result.error_lines, 1)
        self.assertEqual(result.failed_attempts_by_ip["198.51.100.42"], 2)
        self.assertEqual(result.failed_attempts_by_user["admin"], 1)


if __name__ == "__main__":
    unittest.main()
