"""Tests for utils module."""

import os
import tempfile
from unittest.mock import MagicMock, patch

from xyvora.utils import Result, cmd_to_str, run_cmd, save_result


class TestResult:
    def test_has_output_when_stdout_has_content(self):
        r = Result("nmap")
        r.stdout = "PORT  STATE\n22/tcp open"
        assert r.has_output is True

    def test_has_output_when_empty(self):
        r = Result("nmap")
        assert r.has_output is False

    def test_label_with_port(self):
        r = Result("gobuster", 80)
        assert r.label == "gobuster:80"

    def test_label_without_port(self):
        r = Result("enum4linux")
        assert r.label == "enum4linux"


class TestRunCmd:
    @patch("subprocess.run")
    def test_successful_command(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")
        result = run_cmd(["echo", "hello"])
        assert result.success is True
        assert result.stdout == "output"

    @patch("subprocess.run")
    def test_failed_command(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        result = run_cmd(["false"])
        assert result.success is False

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_tool_not_found(self, mock_run):
        result = run_cmd(["nonexistent_tool"])
        assert result.success is False
        assert "Tool not found" in result.stderr

    @patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd="sleep", timeout=1.0))
    def test_timeout(self, mock_run):
        result = run_cmd(["sleep", "999"], timeout=1)
        assert result.success is False
        assert "Timeout" in result.stderr


class TestCmdToStr:
    def test_simple_command(self):
        assert cmd_to_str(["nmap", "-sC", "10.10.10.1"]) == "nmap -sC 10.10.10.1"

    def test_command_with_spaces(self):
        assert cmd_to_str(["echo", "hello world"]) == "echo 'hello world'"


class TestSaveResult:
    def test_saves_non_empty_result(self):
        r = Result("test", 80)
        r.stdout = "some output"
        with tempfile.TemporaryDirectory() as tmp:
            path = save_result(r, tmp)
            assert path is not None
            assert os.path.exists(path)
            with open(path) as f:
                assert f.read() == "some output"

    def test_skips_empty_result(self):
        r = Result("test", 80)
        with tempfile.TemporaryDirectory() as tmp:
            path = save_result(r, tmp)
            assert path is None
