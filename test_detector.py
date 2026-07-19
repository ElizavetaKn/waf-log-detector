import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from waf_log_detector.detector import inspect_request


class DetectorTests(unittest.TestCase):
    def test_detects_encoded_xss(self):
        results = inspect_request("GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1")
        self.assertTrue(any(item.category == "xss" for item in results))

    def test_benign_request_has_no_detection(self):
        results = inspect_request("GET /products?page=2 HTTP/1.1")
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
