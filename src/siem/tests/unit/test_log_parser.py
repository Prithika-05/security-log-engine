import pytest

from siem.exceptions import InvalidLogFormatException
from siem.parsing.log_parser import parse_log_line


def test_parse_valid_log_line():
    line = "2026-09-24T10:00:01 10.0.0.5 POST /login 401"

    entry = parse_log_line(line)

    assert entry.ip_address == "10.0.0.5"
    assert entry.method == "POST"
    assert entry.path == "/login"
    assert entry.status_code == 401


def test_invalid_field_count():
    line = "this is broken"

    with pytest.raises(InvalidLogFormatException):
        parse_log_line(line)


def test_invalid_timestamp():
    line = "not-a-date 10.0.0.5 POST /login 401"

    with pytest.raises(InvalidLogFormatException):
        parse_log_line(line)


def test_invalid_status_code():
    line = "2026-09-24T10:00:01 10.0.0.5 POST /login not-a-number"

    with pytest.raises(InvalidLogFormatException):
        parse_log_line(line)
