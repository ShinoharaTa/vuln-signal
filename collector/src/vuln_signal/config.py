"""設定の読み込み。

環境変数を優先し、env ファイル（既定 ~/.config/vuln-signal/env）は環境に無いキーだけを補う。
tier 判定のルール設定は別の TOML（既定 ~/.config/vuln-signal/rules.toml）から読む。
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping, MutableMapping
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_ENV_FILE = "~/.config/vuln-signal/env"
DEFAULT_RULES_FILE = "~/.config/vuln-signal/rules.toml"
DEFAULT_DATA_DIR = "~/.local/share/vuln-signal"
DEFAULT_INITIAL_LOOKBACK_HOURS = 24
DEFAULT_EPSS_WINDOW_DAYS = 30
DEFAULT_JEV_MODEL = "jev-latest"
DEFAULT_JEV_MIN_CONFIDENCE = 0.6
DEFAULT_JEV_MAX_PER_RUN = 500
DEFAULT_JEV_MAX_CHARS = 4000


@dataclass(frozen=True)
class Config:
    # API キーは repr に出さない（ログや例外表示に漏らさないため）
    nvd_api_key: str = field(default="", repr=False)
    data_dir: Path = field(default_factory=lambda: Path(DEFAULT_DATA_DIR).expanduser())
    nvd_initial_lookback_hours: int = DEFAULT_INITIAL_LOOKBACK_HOURS
    github_token: str = field(default="", repr=False)
    ghsa_initial_lookback_hours: int = DEFAULT_INITIAL_LOOKBACK_HOURS
    epss_window_days: int = DEFAULT_EPSS_WINDOW_DAYS
    rules_file: Path = field(default_factory=lambda: Path(DEFAULT_RULES_FILE).expanduser())
    # VULN_SIGNAL_RULES_FILE で明示した（無ければエラーにする）
    rules_file_required: bool = False
    # Jev（TypeSafe）による前段の仕分け。キーが無ければ triage はスキップ
    typesafe_api_key: str = field(default="", repr=False)
    jev_model: str = DEFAULT_JEV_MODEL
    jev_min_confidence: float = DEFAULT_JEV_MIN_CONFIDENCE
    jev_max_per_run: int = DEFAULT_JEV_MAX_PER_RUN
    jev_max_chars: int = DEFAULT_JEV_MAX_CHARS


class ConfigError(ValueError):
    """環境変数の値が不正。"""


def parse_env_file(text: str) -> dict[str, str]:
    """KEY=VALUE 行を読む。# 行と空行は無視し、値の前後の空白とクォートを外す。"""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_env_file(environ: MutableMapping[str, str]) -> None:
    """env ファイルがあれば読み、環境に無いキーだけを environ に足す。"""
    path = Path(environ.get("VULN_SIGNAL_ENV_FILE") or DEFAULT_ENV_FILE).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    for key, value in parse_env_file(text).items():
        environ.setdefault(key, value)


def from_mapping(env: Mapping[str, str]) -> Config:
    data_dir = Path(env.get("VULN_SIGNAL_DATA_DIR") or DEFAULT_DATA_DIR).expanduser()

    def _int(key: str, default: int) -> int:
        value = env.get(key) or ""
        return int(value) if value else default

    def _float(key: str, default: float) -> float:
        value = env.get(key) or ""
        return float(value) if value else default

    def _positive_int(key: str, default: int) -> int:
        value = _int(key, default)
        if value < 1:
            raise ConfigError(f"{key} must be 1 or more: {value}")
        return value

    return Config(
        nvd_api_key=env.get("NVD_API_KEY", ""),
        data_dir=data_dir,
        nvd_initial_lookback_hours=_int(
            "NVD_INITIAL_LOOKBACK_HOURS", DEFAULT_INITIAL_LOOKBACK_HOURS
        ),
        github_token=env.get("GITHUB_TOKEN", ""),
        ghsa_initial_lookback_hours=_int(
            "GHSA_INITIAL_LOOKBACK_HOURS", DEFAULT_INITIAL_LOOKBACK_HOURS
        ),
        epss_window_days=_int("EPSS_WINDOW_DAYS", DEFAULT_EPSS_WINDOW_DAYS),
        rules_file=Path(env.get("VULN_SIGNAL_RULES_FILE") or DEFAULT_RULES_FILE).expanduser(),
        rules_file_required=bool(env.get("VULN_SIGNAL_RULES_FILE")),
        typesafe_api_key=env.get("TYPESAFE_API_KEY", ""),
        jev_model=env.get("JEV_MODEL") or DEFAULT_JEV_MODEL,
        jev_min_confidence=_float("JEV_MIN_CONFIDENCE", DEFAULT_JEV_MIN_CONFIDENCE),
        jev_max_per_run=_positive_int("JEV_MAX_PER_RUN", DEFAULT_JEV_MAX_PER_RUN),
        jev_max_chars=_positive_int("JEV_MAX_CHARS", DEFAULT_JEV_MAX_CHARS),
    )


def load(environ: Mapping[str, str] | None = None) -> Config:
    # os.environ は書き換えず、コピーに env ファイルの値を足して読む
    merged = dict(os.environ if environ is None else environ)
    load_env_file(merged)
    return from_mapping(merged)


# --- ルール設定（rules.toml） ---


class RulesError(ValueError):
    """rules.toml の内容が不正。"""


@dataclass(frozen=True)
class Thresholds:
    p0_cvss: float = 9.0
    p0_epss: float = 0.10
    p1_cvss: float = 7.0
    p1_epss_percentile: float = 0.90
    nodejs_core_cvss: float = 7.0
    kernel_cvss: float = 8.0
    kernel_epss_percentile: float = 0.90


@dataclass(frozen=True)
class ExtraStack:
    name: str
    cpe_prefix: str


@dataclass(frozen=True)
class Rules:
    thresholds: Thresholds = field(default_factory=Thresholds)
    extra_stacks: tuple[ExtraStack, ...] = ()

    @property
    def version(self) -> str:
        """実効設定を JSON（キー順固定）にした sha256 の先頭 12 桁。"""
        effective = {
            "thresholds": asdict(self.thresholds),
            "stack": {"extra": [asdict(e) for e in self.extra_stacks]},
        }
        text = json.dumps(effective, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _check_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise RulesError(f"unknown key in {where}: {', '.join(unknown)}")


def parse_rules(data: Mapping[str, Any]) -> Rules:
    """TOML を読んだ dict から Rules を作る。書かれていない値は既定値。未知のキーはエラー。"""
    _check_keys(data, {"thresholds", "stack"}, "rules")
    raw_thresholds = data.get("thresholds", {})
    if not isinstance(raw_thresholds, dict):
        raise RulesError("thresholds must be a table")
    names = {f.name for f in fields(Thresholds)}
    _check_keys(raw_thresholds, names, "thresholds")
    values: dict[str, float] = {}
    for key, value in raw_thresholds.items():
        # bool は int の派生なので弾く
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise RulesError(f"thresholds.{key} must be a number")
        # 9 と 9.0 で rules_version が変わらないように float に揃える
        values[key] = float(value)

    raw_stack = data.get("stack", {})
    if not isinstance(raw_stack, dict):
        raise RulesError("stack must be a table")
    _check_keys(raw_stack, {"extra"}, "stack")
    raw_extra = raw_stack.get("extra", [])
    if not isinstance(raw_extra, list):
        raise RulesError("stack.extra must be an array of tables")
    extra: list[ExtraStack] = []
    for item in raw_extra:
        if not isinstance(item, dict):
            raise RulesError("stack.extra must be an array of tables")
        _check_keys(item, {"name", "cpe_prefix"}, "stack.extra")
        name, prefix = item.get("name"), item.get("cpe_prefix")
        if not isinstance(name, str) or not name or not isinstance(prefix, str) or not prefix:
            raise RulesError("stack.extra needs non-empty name and cpe_prefix")
        extra.append(ExtraStack(name, prefix))
    return Rules(Thresholds(**values), tuple(extra))


def load_rules(path: Path, *, required: bool = False) -> Rules:
    """rules.toml を読む。ファイルが無ければ既定値（required ならエラー）。"""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        if required:
            raise RulesError(f"rules file not found: {path}") from e
        return Rules()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise RulesError(f"{path}: {e}") from e
    return parse_rules(data)
