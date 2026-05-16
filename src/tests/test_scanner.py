"""Tests for scanner module."""

import os
import tempfile
from unittest.mock import MagicMock, patch

from xyvora.scanner import get_hosts_entries, identify_services, parse_nmap_xml, probe_http_redirect, probe_http_redirects, save_hosts_entries

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sC -sV -p 22,80,443,445 -oA nmap_output 10.10.10.1">
<host>
  <hostnames><hostname name="dc01.htb.local"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.41"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Apache httpd" version="2.4.41"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows SMB"/></port>
  </ports>
</host>
</nmaprun>"""


class TestParseNmapXml:
    def test_parses_services(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(SAMPLE_NMAP_XML)
            f.flush()
            services = parse_nmap_xml(f.name)
        os.unlink(f.name)
        assert 22 in services
        assert services[22]["name"] == "ssh"
        assert services[22]["product"] == "OpenSSH"
        assert services[80]["name"] == "http"
        assert services[443]["name"] == "https"
        assert services[445]["name"] == "microsoft-ds"

    def test_parses_hostname(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(SAMPLE_NMAP_XML)
            f.flush()
            services = parse_nmap_xml(f.name)
        os.unlink(f.name)
        assert services[22]["hostname"] == "dc01.htb.local"

    def test_empty_file_returns_empty_dict(self):
        assert parse_nmap_xml("/nonexistent/path.xml") == {}


class TestIdentifyServices:
    def test_classifies_all_types(self):
        services = {
            22: {"name": "ssh", "product": "", "version": "", "hostname": ""},
            80: {"name": "http", "product": "", "version": "", "hostname": ""},
            443: {"name": "https", "product": "", "version": "", "hostname": ""},
            445: {"name": "microsoft-ds", "product": "", "version": "", "hostname": ""},
            21: {"name": "ftp", "product": "", "version": "", "hostname": ""},
            88: {"name": "kerberos-sec", "product": "", "version": "", "hostname": ""},
        }
        result = identify_services(services)
        assert "http" in result
        assert 80 in result["http"] and 443 in result["http"]
        assert "ssh" in result
        assert "smb" in result
        assert "ftp" in result
        assert "ad" in result

    def test_empty_services(self):
        assert identify_services({}) == {}

    def test_kerberos_triggers_ad(self):
        services = {88: {"name": "kerberos-sec", "product": "", "version": "", "hostname": ""}}
        result = identify_services(services)
        assert "ad" in result


class TestGetHostsEntries:
    def test_ignores_target_ip(self):
        services = {80: {"name": "http", "product": "", "version": "", "hostname": "10.10.10.1"}}
        assert get_hosts_entries("10.10.10.1", services) == []

    def test_ignores_localhost(self):
        services = {80: {"name": "http", "product": "", "version": "", "hostname": "localhost"}}
        assert get_hosts_entries("10.10.10.1", services) == []

    def test_ignores_empty_hostname(self):
        services = {80: {"name": "http", "product": "", "version": "", "hostname": ""}}
        assert get_hosts_entries("10.10.10.1", services) == []

    def test_collects_unique_hostnames(self):
        services = {
            80: {"name": "http", "product": "", "version": "", "hostname": "dc01.htb.local"},
            445: {"name": "smb", "product": "", "version": "", "hostname": "dc01.htb.local"},
        }
        entries = get_hosts_entries("10.10.10.1", services)
        # Returns entries for hostnames not resolving to target
        # (will fail DNS lookup in test → returns "no DNS record")
        assert len(entries) == 1
        assert entries[0][0] == "dc01.htb.local"
        assert "no DNS record" in entries[0][1]


class TestSaveHostsEntries:
    def test_returns_none_for_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            assert save_hosts_entries("10.10.10.1", [], tmp) is None

    def test_saves_entries_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = [("dc01.htb.local", "no DNS record")]
            path = save_hosts_entries("10.10.10.1", entries, tmp)
            assert path is not None
            assert os.path.exists(path)
            content = open(path, encoding="utf-8").read()
            assert "10.10.10.1\tdc01.htb.local" in content
            assert "no DNS record" in content


class TestGetHostsEntriesWithExtra:
    def test_merges_extra_hostnames_from_http(self):
        services = {80: {"name": "http", "product": "", "version": "", "hostname": ""}}
        entries = get_hosts_entries("10.10.10.1", services, {"helix.htb"})
        assert len(entries) == 1
        assert entries[0][0] == "helix.htb"
        assert "no DNS record" in entries[0][1]

    def test_deduplicates_nmap_and_extra(self):
        services = {80: {"name": "http", "product": "", "version": "", "hostname": "dc01.htb.local"}}
        entries = get_hosts_entries("10.10.10.1", services, {"dc01.htb.local"})
        assert len(entries) == 1  # deduplicated


class TestProbeHttpRedirect:
    @patch("xyvora.scanner.http.client.HTTPConnection")
    def test_extracts_hostname_from_302_location(self, mock_conn):
        mock_resp = MagicMock()
        mock_resp.status = 302
        mock_resp.getheader.return_value = "http://helix.htb/"
        mock_resp.read.return_value = b""
        mock_conn.return_value.getresponse.return_value = mock_resp

        result = probe_http_redirect("10.10.10.1", 80)
        assert result == "helix.htb"

    @patch("xyvora.scanner.http.client.HTTPConnection")
    def test_returns_none_for_200(self, mock_conn):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheader.return_value = None
        mock_resp.read.return_value = b""
        mock_conn.return_value.getresponse.return_value = mock_resp

        result = probe_http_redirect("10.10.10.1", 80)
        assert result is None

    @patch("xyvora.scanner.http.client.HTTPConnection")
    def test_returns_none_on_connection_error(self, mock_conn):
        mock_conn.side_effect = OSError("Connection refused")

        result = probe_http_redirect("10.10.10.1", 80)
        assert result is None


class TestProbeHttpRedirects:
    @patch("xyvora.scanner.probe_http_redirect")
    def test_maps_domain_to_hostnames(self, mock_probe):
        mock_probe.side_effect = lambda target, port, scheme: {
            ("10.10.10.1", 80, "http"): "www.helix.htb",
            ("10.10.10.1", 80, "https"): None,
        }.get((target, port, scheme))

        result = probe_http_redirects("10.10.10.1", [80])
        assert "helix.htb" in result
        assert "www.helix.htb" in result["helix.htb"]

    @patch("xyvora.scanner.probe_http_redirect", return_value=None)
    def test_empty_when_no_redirects(self, mock_probe):
        result = probe_http_redirects("10.10.10.1", [80])
        assert result == {}
