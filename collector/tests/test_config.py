from pathlib import Path

import pytest

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
        "NVD_INITIAL_LOOKBACK_HOURS=48\n"
        "GITHUB_TOKEN=gh-secret\n"
        "GHSA_INITIAL_LOOKBACK_HOURS=12\n"
        "EPSS_WINDOW_DAYS=7\n",
    )
    cfg = config.load({"VULN_SIGNAL_ENV_FILE": str(env_file)})
    assert cfg.nvd_api_key == "secret-key"
    assert cfg.data_dir == Path("/tmp/vs data")
    assert cfg.nvd_initial_lookback_hours == 48
    assert cfg.github_token == "gh-secret"
    assert cfg.ghsa_initial_lookback_hours == 12
    assert cfg.epss_window_days == 7


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
    assert cfg.github_token == ""
    assert cfg.ghsa_initial_lookback_hours == 24
    assert cfg.epss_window_days == 30
    assert cfg.rules_file == Path("~/.config/vuln-signal/rules.toml").expanduser()
    assert cfg.typesafe_api_key == ""
    assert cfg.jev_model == "jev-latest"
    assert cfg.jev_min_confidence == 0.6
    assert cfg.jev_max_per_run == 500
    assert cfg.jev_max_chars == 4000


def test_load_does_not_modify_os_environ(tmp_path, monkeypatch):
    env_file = _write(tmp_path, "VULN_SIGNAL_TEST_ONLY=1\n")
    monkeypatch.setenv("VULN_SIGNAL_ENV_FILE", str(env_file))
    monkeypatch.delenv("VULN_SIGNAL_TEST_ONLY", raising=False)
    config.load()
    import os

    assert "VULN_SIGNAL_TEST_ONLY" not in os.environ


def test_api_key_not_in_repr(tmp_path):
    cfg = config.load(
        {
            "VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope"),
            "NVD_API_KEY": "s3cr3t",
            "GITHUB_TOKEN": "t0k3n",
            "TYPESAFE_API_KEY": "ts-k3y",
        }
    )
    assert "s3cr3t" not in repr(cfg)
    assert "t0k3n" not in repr(cfg)
    assert "ts-k3y" not in repr(cfg)


def test_jev_settings_from_env(tmp_path):
    cfg = config.load(
        {
            "VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope"),
            "TYPESAFE_API_KEY": "ts-k3y",
            "JEV_MODEL": "jev-1.14.0",
            "JEV_MIN_CONFIDENCE": "0.75",
            "JEV_MAX_PER_RUN": "20",
            "JEV_MAX_CHARS": "1000",
        }
    )
    assert cfg.typesafe_api_key == "ts-k3y"
    assert cfg.jev_model == "jev-1.14.0"
    assert cfg.jev_min_confidence == 0.75
    assert (cfg.jev_max_per_run, cfg.jev_max_chars) == (20, 1000)


def test_rules_file_from_env(tmp_path):
    cfg = config.load(
        {
            "VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope"),
            "VULN_SIGNAL_RULES_FILE": str(tmp_path / "r.toml"),
        }
    )
    assert cfg.rules_file == tmp_path / "r.toml"
    assert cfg.rules_file_required


def test_default_rules_file_not_required(tmp_path):
    cfg = config.load(
        {"VULN_SIGNAL_ENV_FILE": str(tmp_path / "nope"), "VULN_SIGNAL_RULES_FILE": ""}
    )
    assert not cfg.rules_file_required


def test_required_rules_file_missing_is_error(tmp_path):
    with pytest.raises(config.RulesError, match="not found"):
        config.load_rules(tmp_path / "nope.toml", required=True)
    p = tmp_path / "rules.toml"
    p.write_text("", encoding="utf-8")
    assert config.load_rules(p, required=True) == config.Rules()


def test_missing_rules_file_uses_defaults(tmp_path):
    rules = config.load_rules(tmp_path / "nope.toml")
    assert rules == config.Rules()
    t = rules.thresholds
    assert (t.p0_cvss, t.p0_epss, t.p1_cvss, t.p1_epss_percentile) == (9.0, 0.10, 7.0, 0.90)
    assert (t.nodejs_core_cvss, t.kernel_cvss, t.kernel_epss_percentile) == (7.0, 8.0, 0.90)
    assert rules.extra_stacks == ()
    assert len(rules.version) == 12


def test_rules_file_overrides_and_extra(tmp_path):
    p = tmp_path / "rules.toml"
    p.write_text(
        "[thresholds]\np0_cvss = 8.5\nkernel_cvss = 9\n\n"
        '[[stack.extra]]\nname = "nginx"\ncpe_prefix = "cpe:2.3:a:f5:nginx:"\n',
        encoding="utf-8",
    )
    rules = config.load_rules(p)
    assert rules.thresholds.p0_cvss == 8.5
    assert rules.thresholds.kernel_cvss == 9.0
    assert rules.thresholds.p1_cvss == 7.0
    assert rules.extra_stacks == (config.ExtraStack("nginx", "cpe:2.3:a:f5:nginx:"),)


@pytest.mark.parametrize(
    "text",
    [
        "[thresholds]\np2_cvss = 1.0\n",
        "[tresholds]\n",
        "[stack]\ndistro = 1\n",
        '[[stack.extra]]\nname = "x"\ncpe_prefix = "cpe:"\nweight = 1\n',
        '[[stack.extra]]\nname = "x"\n',
        '[thresholds]\np0_cvss = "9"\n',
        "[thresholds]\np0_cvss = true\n",
        "not toml = = 1\n",
    ],
)
def test_bad_rules_file_is_error(tmp_path, text):
    p = tmp_path / "rules.toml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(config.RulesError):
        config.load_rules(p)


def test_rules_version_changes_with_settings():
    base = config.Rules()
    assert base.version == config.Rules().version
    # 既定値を明示しても同じ（int / float の違いも吸収する）
    assert config.parse_rules({"thresholds": {"p0_cvss": 9}}).version == base.version
    assert config.parse_rules({"thresholds": {"p0_cvss": 8.0}}).version != base.version
    extra = {"stack": {"extra": [{"name": "nginx", "cpe_prefix": "cpe:2.3:a:f5:nginx:"}]}}
    assert config.parse_rules(extra).version != base.version


def test_example_rules_file_is_defaults():
    example = Path(__file__).parent.parent / "rules.example.toml"
    assert config.load_rules(example) == config.Rules()
