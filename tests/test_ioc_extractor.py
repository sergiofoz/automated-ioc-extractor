import os
import sys

# Make the script at the repo root importable as a module.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ioc_extractor  # noqa: E402


# ---------------------------------------------------------------------------
# apply_filters
# ---------------------------------------------------------------------------
def test_apply_filters_unknown_plugin_returns_output_unchanged():
    output = "anything\ngoes here"
    assert ioc_extractor.apply_filters("does.not.exist", output) == output


def test_apply_filters_netscan_keeps_only_ip_or_url_lines():
    output = "\n".join([
        "PROTO 10.0.0.5 ESTABLISHED",
        "no address on this line",
        "GET http://evil.example/c2",
    ])
    filtered = ioc_extractor.apply_filters("windows.netscan", output)
    lines = filtered.splitlines()
    assert "PROTO 10.0.0.5 ESTABLISHED" in lines
    assert "GET http://evil.example/c2" in lines
    assert "no address on this line" not in lines


def test_apply_filters_ldrmodule_matches_without_trailing_newline():
    # Regression: the pattern used to require a trailing \n, which never
    # matched because splitlines() strips it -> the filter was always empty.
    line = "0x1000 evil.dll True False True"
    output = "\n".join([line, "0x2000 ok.dll True True True"])
    filtered = ioc_extractor.apply_filters("windows.ldrmodule", output)
    assert filtered == line


def test_apply_filters_cmdline_matches_suspicious_tokens():
    output = "\n".join([
        "1234 notepad.exe",
        "5678 powershell.exe -EncodedCommand AAAA",
    ])
    filtered = ioc_extractor.apply_filters("windows.cmdline", output).splitlines()
    assert any("powershell" in line for line in filtered)
    assert "1234 notepad.exe" not in filtered


# ---------------------------------------------------------------------------
# extract_results
# ---------------------------------------------------------------------------
def _sample_report():
    return {
        "behavior": {
            "summary": {
                "files": ["C:\\Temp\\a.exe", "C:\\Temp\\b.dll"],
                "keys": ["HKLM\\Run"],
            }
        },
        "network": {
            "hosts": ["1.2.3.4", "5.6.7.8"],
            "domains": [
                {"domain": "evil.example", "ip": "1.2.3.4"},
                {"domain": "c2.example", "ip": "5.6.7.8"},
            ],
        },
    }


def test_extract_results_domains_written_one_per_line(tmp_path):
    # Regression: domains used to be written by joining a *string* with '\n',
    # which inserted a newline between every character.
    ioc_extractor.extract_results(_sample_report(), str(tmp_path))
    content = (tmp_path / "domains_results.txt").read_text()
    assert content == "evil.example;1.2.3.4\nc2.example;5.6.7.8\n"


def test_extract_results_hosts_and_summary_files(tmp_path):
    ioc_extractor.extract_results(_sample_report(), str(tmp_path))

    hosts = (tmp_path / "hosts_results.txt").read_text()
    assert hosts == "1.2.3.4\n5.6.7.8"

    files = (tmp_path / "files_results.txt").read_text()
    assert files == "C:\\Temp\\a.exe\nC:\\Temp\\b.dll"

    keys = (tmp_path / "keys_results.txt").read_text()
    assert keys == "HKLM\\Run"


def test_extract_results_missing_keys_does_not_raise(tmp_path):
    # extract_results swallows errors; an empty report must not crash.
    ioc_extractor.extract_results({}, str(tmp_path))
