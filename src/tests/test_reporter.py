"""Tests for reporter module."""

import os
import tempfile

from xyvora.reporter import generate
from xyvora.utils import Result


def test_generate_empty_report():
    with tempfile.TemporaryDirectory() as tmp:
        path = generate("10.10.10.1", tmp, {}, {"web": []}, 0.5)
        assert os.path.exists(path)
        content = open(path, encoding="utf-8").read()
        assert "xyvora Report" in content
        assert "10.10.10.1" in content
        assert "No results" in content


def test_generate_with_results():
    r = Result("gobuster", 80)
    r.stdout = "/admin\n/login\n"
    r.success = True
    r.elapsed = 10.0

    with tempfile.TemporaryDirectory() as tmp:
        services = {80: {"name": "http", "product": "Apache", "version": "2.4"}}
        path = generate("10.10.10.1", tmp, services, {"web": [r]}, 15.0)
        content = open(path, encoding="utf-8").read()
        assert "gobuster:80" in content
        assert "/admin" in content
        assert "80" in content
        assert "Apache" in content


def test_generate_skips_empty_results():
    r_empty = Result("nikto", 80)
    r_filled = Result("gobuster", 80)
    r_filled.stdout = "found something"

    with tempfile.TemporaryDirectory() as tmp:
        path = generate("10.10.10.1", tmp, {}, {"web": [r_empty, r_filled]}, 1.0)
        content = open(path, encoding="utf-8").read()
        assert "gobuster:80" in content
        assert "nikto:80" not in content


def test_generate_truncates_long_output():
    r = Result("gobuster", 80)
    r.stdout = "A" * 6000
    r.success = True

    with tempfile.TemporaryDirectory() as tmp:
        path = generate("10.10.10.1", tmp, {}, {"web": [r]}, 1.0)
        content = open(path, encoding="utf-8").read()
        assert "truncated" in content
        # Report header + section boilerplate + 5000 chars of truncated A's
        assert len(content) < 100 + 5000 + 300
