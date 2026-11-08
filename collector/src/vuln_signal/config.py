"""設定の読み込み。

環境変数を優先し、env ファイル（既定 ~/.config/vuln-signal/env）は環境に無いキーだけを補う。
"""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ENV_FILE = "~/.config/vuln-signal/env"
DEFAULT_DATA_DIR = "~/.local/share/vuln-signal"
DEFAULT_INITIAL_LOOKBACK_HOURS = 24


@dataclass(frozen=True)
class Config:
    # API キーは repr に出さない（ログや例外表示に漏らさないため）
    nvd_api_key: str = field(default="", repr=False)
    data_dir: Path = field(default_factory=lambda: Path(DEFAULT_DATA_DIR).expanduser())
    nvd_initial_lookback_hours: int = DEFAULT_INITIAL_LOOKBACK_HOURS


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
    hours = env.get("NVD_INITIAL_LOOKBACK_HOURS") or ""
    return Config(
        nvd_api_key=env.get("NVD_API_KEY", ""),
        data_dir=data_dir,
        nvd_initial_lookback_hours=int(hours) if hours else DEFAULT_INITIAL_LOOKBACK_HOURS,
    )


def load(environ: Mapping[str, str] | None = None) -> Config:
    # os.environ は書き換えず、コピーに env ファイルの値を足して読む
    merged = dict(os.environ if environ is None else environ)
    load_env_file(merged)
    return from_mapping(merged)
