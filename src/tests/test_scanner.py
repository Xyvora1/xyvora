"""Tests for scanner module."""

import os
import tempfile

from xyvora.scanner import identify_services, parse_nmap_xml

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
