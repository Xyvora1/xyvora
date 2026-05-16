"""Smoke test: verify all modules import correctly."""


def test_import_package():
    import xyvora
    assert xyvora.__version__ == "0.1.0"


def test_import_utils():
    from xyvora import utils
    assert hasattr(utils, "run_cmd")
    assert hasattr(utils, "Result")


def test_import_modules():
    from xyvora.modules import ad, ftp, http, smb, ssh
    assert hasattr(http, "run_http")
    assert hasattr(smb, "run_smb")
    assert hasattr(ftp, "run_ftp")
    assert hasattr(ssh, "run_ssh")
    assert hasattr(ad, "run_ad")


def test_import_scanner():
    from xyvora import scanner
    assert hasattr(scanner, "scan_ports")
    assert hasattr(scanner, "deep_scan")
    assert hasattr(scanner, "identify_services")


def test_import_reporter():
    from xyvora import reporter
    assert hasattr(reporter, "generate")
