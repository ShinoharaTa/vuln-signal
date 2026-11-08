from pathlib import Path

from vuln_signal import config


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "env"
    p.write_text(text, encoding="utf-8")
    return p


def test_reads_env_file_with_comments_quotes_and_blanks(tmp_path):
    env_file = _write(
        tmp_path,
        "# comment\n"
        "\n"
        "NVD_API_KEY = 'secret-key'  \n"
        'VULN_SIGNAL_DATA_DIR="/tmp/vs data"\n'
        "NVD_INITIAL_LOOKBACK_HOURS=48\n",
    )
    cfg = config.load({"VULN_SIGNAL_ENV_FILE": str(env_file)})
    assert cfg.nvd_api_key == "secret-key"
    assert cfg.data_dir == Path("/tmp/vs data")
    assert cfg.nvd_initial_lookback_hours == 48


def test_existing_environment_wins(tmp_path):
    env_file = _write(tmp_path, "NVD_API_KEY=from-file\nNVD_INITIAL_LOOKBACK_HOURS=48\n")
    cfg = config.load({"VULN_SIGNAL_ENV_FILE": str(env_file), "NVD_API_KEY": "from-env"})
    assert cfg.nvd_api_key == "from-env"
    assert cfg.nvd_initial_lookback_hours == 48


def test_missing_env_file_uses_defaults(tmp_path):
    cfg = config.load({"VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope")})
    assert cfg.nvd_api_key == ""
    assert cfg.data_dir == Path("~/.local/share/vuln-signal").expanduser()
    assert cfg.nvd_initial_lookback_hours == 24


def test_load_does_not_modify_os_environ(tmp_path, monkeypatch):
    env_file = _write(tmp_path, "VULN_SIGNAL_TEST_ONLY=1\n")
    monkeypatch.setenv("VULN_SIGNAL_ENV_FILE", str(env_file))
    monkeypatch.delenv("VULN_SIGNAL_TEST_ONLY", raising=False)
    config.load()
    import os

    assert "VULN_SIGNAL_TEST_ONLY" not in os.environ


def test_api_key_not_in_repr(tmp_path):
    cfg = config.load({"VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope"), "NVD_API_KEY": "s3cr3t"})
    assert "s3cr3t" not in repr(cfg)
