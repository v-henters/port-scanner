Portsense

Portsense is a lightweight scaffold for a port-scan analysis tool. It parses local scan outputs (e.g., nmap XML), performs simple risk and confidence assessments, and outputs JSON or Markdown reports.

Status: scaffold with runnable CLI and TODO markers. No network actions are performed by the tool itself.

Requirements
- Python 3.11+

Installation (editable)
```
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

CLI Usage
```
portsense --help
python -m portsense --help
```

Basic example (with an nmap XML file):
```
portsense analyze --input path/to/scan.xml --format json > report.json
portsense analyze --input path/to/scan.xml --format md > report.md
```

Project Structure
See directories under `portsense/`, `scripts/`, `examples/`, and `tests/` for the scaffolded modules and examples.

Tests
```
pip install pytest
python -m pytest -q
```

License
MIT