from vuln_signal.sources.http import shorten_log_value


def test_short_values_are_kept():
    assert shorten_log_value("2099-01-01T00:00:00.000Z") == "2099-01-01T00:00:00.000Z"
    assert shorten_log_value("a" * 80) == "a" * 80
    assert shorten_log_value("CVE-1,CVE-2,CVE-3,CVE-4") == "CVE-1,CVE-2,CVE-3,CVE-4"
    assert shorten_log_value(100) == 100
    assert shorten_log_value(None) is None


def test_long_string_keeps_head_60_chars():
    assert shorten_log_value("a" * 81) == "a" * 60 + "…(+21 chars)"


def test_long_comma_list_keeps_first_3_items():
    ids = [f"CVE-2020-{i:04d}" for i in range(100)]
    expected = "CVE-2020-0000,CVE-2020-0001,CVE-2020-0002…(+97 items)"
    assert shorten_log_value(",".join(ids)) == expected
