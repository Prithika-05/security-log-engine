import pytest

from siem.main import parse_args


def test_parse_log_file_argument(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "siem",
            "--log-file",
            "data/sample.log",
        ],
    )

    args = parse_args()

    assert args.log_file == "data/sample.log"

def test_missing_log_file_argument(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["siem"],
    )

    with pytest.raises(SystemExit) as exc_info:
        parse_args()

    assert exc_info.value.code == 2