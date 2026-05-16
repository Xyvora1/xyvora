"""Tests for HTTP module."""

from unittest.mock import patch

from xyvora.modules.http import _run_gobuster, _run_nikto, _run_whatweb, run_http
from xyvora.utils import Result


class TestRunGobuster:
    @patch("xyvora.modules.http.run_cmd")
    def test_uses_dirbuster_wordlist(self, mock_run):
        mock_run.return_value = Result("gobuster", 80)
        _run_gobuster("http://10.10.10.1:80", 80)
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "gobuster"
        assert "dir" in cmd
        assert "http://10.10.10.1:80" in cmd
        assert any("directory-list-2.3-medium.txt" in c for c in cmd)


class TestRunNikto:
    @patch("xyvora.modules.http.run_cmd")
    def test_runs_nikto_with_tuning(self, mock_run):
        mock_run.return_value = Result("nikto", 80)
        _run_nikto("http://10.10.10.1:80", 80)
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "nikto"


class TestRunWhatweb:
    @patch("xyvora.modules.http.run_cmd")
    def test_runs_whatweb(self, mock_run):
        mock_run.return_value = Result("whatweb", 80)
        _run_whatweb("http://10.10.10.1:80", 80)
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "whatweb"


def _fake_as_completed(futures_dict):
    for f in futures_dict:
        yield f


class TestRunHttp:
    @patch("xyvora.modules.http.as_completed", side_effect=_fake_as_completed)
    @patch("xyvora.modules.http._run_gobuster")
    @patch("xyvora.modules.http._run_nikto")
    @patch("xyvora.modules.http._run_whatweb")
    @patch("xyvora.modules.http.save_result")
    def test_runs_all_tools_for_each_port(self, mock_save, mock_whatweb, mock_nikto, mock_gobuster, mock_ac):
        r = Result("gobuster", 80)
        r.stdout = "/admin"
        r.success = True
        mock_gobuster.return_value = r
        mock_nikto.return_value = Result("nikto", 80)
        mock_whatweb.return_value = Result("whatweb", 80)

        results = run_http("10.10.10.1", [80, 443], dry_run=False, out_dir="/tmp/test")
        assert len(results) == 6  # 3 tools × 2 ports
