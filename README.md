# WAF Log Detector

A defensive analyzer for HTTP access logs. It detects suspicious request patterns commonly associated with web attacks and produces structured alerts.

## What it demonstrates

- WAF / AppSec fundamentals
- HTTP request analysis
- Detection rules for suspicious patterns
- URL decoding
- Severity classification
- Defensive security automation in Python

## Supported detections

- SQL injection indicators
- Cross-site scripting indicators
- Path traversal indicators
- Command injection indicators

## Run

```bash
python -m waf_log_detector.cli examples/access.log --output alerts.json
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The example log contains synthetic requests for defensive training only.
