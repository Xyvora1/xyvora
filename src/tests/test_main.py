"""Tests for main orchestrator."""

import io
import sys
from unittest.mock import patch

from xyvora.main import run
from xyvora.utils import Result


class FakeFuture:
    """Mimics a completed concurrent.futures.Future."""
    def __init__(self, result):
        self._result = result
    def result(self):
        return self._result
    def exception(self):
        return None


def fake_as_completed(futures_dict):
    """Yield futures immediately in insertion order."""
    for f in futures_dict:
        yield f


@patch("xyvora.main.as_completed", side_effect=fake_as_completed)
@patch("xyvora.main.scan_ports")
@patch("xyvora.main.deep_scan")
@patch("xyvora.main.generate")
def test_run_no_ports(mock_gen, mock_deep, mock_scan, mock_ac):
    """Exit code 1 when no open ports found."""
    mock_scan.return_value = ([], None)
    exit_code = run("10.10.10.1")
    assert exit_code == 1
    mock_deep.assert_not_called()


@patch("xyvora.main.as_completed", side_effect=fake_as_completed)
@patch("xyvora.main.scan_ports")
@patch("xyvora.main.deep_scan")
@patch("xyvora.main.generate")
def test_run_no_services(mock_gen, mock_deep, mock_scan, mock_ac):
    """Exit code 2 when no services identified."""
    mock_scan.return_value = ([22, 80], None)
    mock_deep.return_value = ({}, None)
    exit_code = run("10.10.10.1")
    assert exit_code == 2


@patch("xyvora.main.as_completed", side_effect=fake_as_completed)
@patch("xyvora.main.scan_ports")
@patch("xyvora.main.deep_scan")
@patch("xyvora.main.generate")
@patch("xyvora.main.run_http")
@patch("xyvora.main.run_ssh")
@patch("xyvora.main.run_smb")
@patch("xyvora.main.run_ftp")
@patch("xyvora.main.run_ad")
def test_run_success(mock_ad, mock_ftp, mock_smb, mock_ssh, mock_http, mock_gen, mock_deep, mock_scan, mock_ac):
    """Successful run returns 0 and generates report."""
    mock_scan.return_value = ([22, 80, 445, 88], None)
    mock_deep.return_value = ({
        22: {"name": "ssh", "product": "", "version": "", "hostname": ""},
        80: {"name": "http", "product": "", "version": "", "hostname": ""},
        445: {"name": "microsoft-ds", "product": "", "version": "", "hostname": ""},
        88: {"name": "kerberos-sec", "product": "", "version": "", "hostname": ""},
    }, None)
    mock_http.return_value = [Result("gobuster", 80)]
    mock_ssh.return_value = [Result("ssh-audit", 22)]
    mock_smb.return_value = [Result("enum4linux")]
    mock_ad.return_value = []
    mock_ftp.return_value = []
    mock_gen.return_value = "results/10.10.10.1/report.md"

    exit_code = run("10.10.10.1")
    assert exit_code == 0


@patch("xyvora.main.as_completed", side_effect=fake_as_completed)
@patch("xyvora.main.scan_ports")
@patch("xyvora.main.deep_scan")
@patch("xyvora.main.generate")
@patch("xyvora.main.run_http")
@patch("xyvora.main.run_ssh")
@patch("xyvora.main.run_smb")
@patch("xyvora.main.run_ftp")
@patch("xyvora.main.run_ad")
def test_dry_run(mock_ad, mock_ftp, mock_smb, mock_ssh, mock_http, mock_gen, mock_deep, mock_scan, mock_ac):
    """Dry-run mode does not call any modules."""
    mock_scan.return_value = ([22, 80], "DRY-RUN: rustscan...")
    mock_deep.return_value = ({
        22: {"name": "ssh", "product": "", "version": "", "hostname": ""},
        80: {"name": "http", "product": "", "version": "", "hostname": ""},
    }, None)

    captured = io.StringIO()
    sys.stdout = captured
    exit_code = run("10.10.10.1", dry_run=True)
    sys.stdout = sys.__stdout__

    assert exit_code == 0
    # In dry-run, the module runners still execute but they just print commands
    mock_http.assert_called()
    mock_ssh.assert_called()


@patch("xyvora.main.as_completed", side_effect=fake_as_completed)
@patch("xyvora.main.scan_ports")
@patch("xyvora.main.deep_scan")
@patch("xyvora.main.generate")
@patch("xyvora.main.run_ad")
def test_credentials_passed_to_ad(mock_ad, mock_gen, mock_deep, mock_scan, mock_ac):
    """AD module receives credentials when -u and -p are provided."""
    mock_scan.return_value = ([88, 389], None)
    mock_deep.return_value = ({
        88: {"name": "kerberos-sec", "product": "", "version": "", "hostname": ""},
        389: {"name": "ldap", "product": "", "version": "", "hostname": ""},
    }, None)
    mock_ad.return_value = []
    mock_gen.return_value = "results/10.10.10.1/report.md"

    run("10.10.10.1", username="admin", password="Pass123", domain="htb.local")
    mock_ad.assert_called_once()
    args = mock_ad.call_args[0]
    assert args[2] == "admin"
    assert args[3] == "Pass123"
    assert args[4] == "htb.local"
