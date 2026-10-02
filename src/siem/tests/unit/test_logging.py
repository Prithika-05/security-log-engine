import logging


def test_logging(caplog):
    with caplog.at_level(logging.INFO):
        logging.getLogger("test").info("Security event detected")

    assert "Security event detected" in caplog.text