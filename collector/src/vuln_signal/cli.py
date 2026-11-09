"""コマンドライン。

vuln-signal sync nvd|kev|epss|ghsa|all / classify / triage / report / db path。
"""

from __future__ import annotations

import logging
from contextlib import ExitStack
from datetime import UTC, datetime
from typing import Annotated

import typer

from vuln_signal import config
from vuln_signal.config import Config, RulesError
from vuln_signal.report import build_report, format_report
from vuln_signal.rules import TIERS
from vuln_signal.sources.epss import EpssClient
from vuln_signal.sources.ghsa import GhsaClient
from vuln_signal.sources.jev import JevClient
from vuln_signal.sources.kev import KevClient
from vuln_signal.sources.nvd import NvdClient
from vuln_signal.store import Store, db_path, iso, parse_iso
from vuln_signal.sync import SOURCE_CLASSIFY, classify, sync_epss, sync_ghsa, sync_kev, sync_nvd
from vuln_signal.triage import triage

app = typer.Typer(no_args_is_help=True, add_completion=False)
sync_app = typer.Typer(no_args_is_help=True, help="一次ソースから取得して作業 DB に反映する。")
db_app = typer.Typer(no_args_is_help=True, help="作業 DB の操作。")
app.add_typer(sync_app, name="sync")
app.add_typer(db_app, name="db")


@app.callback()
def main() -> None:
    """vuln-signal collector."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@sync_app.callback()
def sync_main() -> None:
    pass


@db_app.callback()
def db_main() -> None:
    pass


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_iso(value)
    except ValueError as e:
        raise typer.BadParameter(f"ISO 8601 で指定する（例 2026-11-06T00:00:00Z）: {value}") from e


DryRunOption = Annotated[bool, typer.Option("--dry-run", help="取得と差分計算だけして書かない")]
SinceOption = Annotated[str | None, typer.Option(help="開始時刻（UTC、例 2026-11-06T00:00:00Z）")]


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _dry_label(dry_run: bool) -> str:
    return " (dry-run, not written)" if dry_run else ""


def _echo_events(events: dict[str, int]) -> None:
    for kind, n in sorted(events.items()):
        typer.echo(f"event {kind}: {n}")


def _fail(source: str, e: Exception, *secrets: str) -> bool:
    text = f"{type(e).__name__}: {e}"
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    typer.echo(f"sync {source} failed: {text}", err=True)
    return False


# 各 _run_* は結果を表示し、成功なら True を返す（sync all でまとめて回すため例外にしない）。
# Store.open やクライアント生成の失敗も同じく 1 行のエラーにする


def _run_nvd(cfg: Config, since: datetime | None, dry_run: bool) -> bool:
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            client = NvdClient(cfg.nvd_api_key)
            stack.callback(client.close)
            result = sync_nvd(
                store,
                client,
                _now(),
                since,
                lookback_hours=cfg.nvd_initial_lookback_hours,
                dry_run=dry_run,
            )
    except Exception as e:
        return _fail("nvd", e, cfg.nvd_api_key)

    typer.echo(f"nvd {iso(result.start)} .. {iso(result.end)}{_dry_label(dry_run)}")
    typer.echo(f"requests: {client.request_count}")
    typer.echo(f"fetched: {result.fetched}")
    typer.echo(f"new: {result.new}")
    _echo_events(result.events)
    return True


def _run_kev(cfg: Config, dry_run: bool) -> bool:
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            client = KevClient()
            stack.callback(client.close)
            result = sync_kev(store, client, _now(), dry_run=dry_run)
    except Exception as e:
        return _fail("kev", e)

    typer.echo(f"kev catalogVersion {result.catalog_version or '-'}{_dry_label(dry_run)}")
    typer.echo(f"requests: {client.request_count}")
    if result.not_modified:
        typer.echo("not modified (304)")
    if result.bootstrap:
        typer.echo("bootstrap: true")
    typer.echo(f"fetched: {result.fetched}")
    _echo_events(result.events)
    return True


def _run_epss(cfg: Config, force: bool, dry_run: bool) -> bool:
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            client = EpssClient()
            stack.callback(client.close)
            result = sync_epss(
                store,
                client,
                _now(),
                window_days=cfg.epss_window_days,
                force=force,
                dry_run=dry_run,
            )
    except Exception as e:
        return _fail("epss", e)

    if result.skipped:
        typer.echo(f"epss skipped: already have {result.model_date}")
        return True
    typer.echo(f"epss model_date {result.model_date or '-'}{_dry_label(dry_run)}")
    typer.echo(f"requests: {client.request_count}")
    typer.echo(f"targets: {result.targets}")
    typer.echo(f"fetched: {result.fetched}")
    _echo_events(result.events)
    return True


def _run_ghsa(cfg: Config, since: datetime | None, dry_run: bool) -> bool:
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            client = GhsaClient(cfg.github_token)
            stack.callback(client.close)
            result = sync_ghsa(
                store,
                client,
                _now(),
                since,
                lookback_hours=cfg.ghsa_initial_lookback_hours,
                dry_run=dry_run,
            )
    except Exception as e:
        return _fail("ghsa", e, cfg.github_token)

    typer.echo(f"ghsa {iso(result.start)} .. {iso(result.end)}{_dry_label(dry_run)}")
    typer.echo(f"requests: {client.request_count}")
    typer.echo(f"fetched: {result.fetched}")
    _echo_events(result.events)
    return True


def _record_classify_error(cfg: Config, text: str) -> None:
    """classify の外（ルール読み込み）で失敗したときも sync_state に残す。開けなければ諦める。"""
    try:
        store = Store.open(cfg.data_dir)
    except Exception:
        return
    try:
        store.mark_sync_error(SOURCE_CLASSIFY, iso(_now()), text)
    except Exception:
        pass
    finally:
        store.close()


def _run_classify(cfg: Config, all_subjects: bool, dry_run: bool) -> bool:
    try:
        rules = config.load_rules(cfg.rules_file, required=cfg.rules_file_required)
    except RulesError as e:
        text = f"{type(e).__name__}: {e}"
        if not dry_run:
            _record_classify_error(cfg, text)
        typer.echo(f"classify failed: {text}", err=True)
        return False
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            result = classify(store, rules, _now(), all_subjects=all_subjects, dry_run=dry_run)
    except Exception as e:
        typer.echo(f"classify failed: {type(e).__name__}: {e}", err=True)
        return False

    mode = "all" if result.all else "diff"
    typer.echo(f"classify {mode} rules_version {result.rules_version}{_dry_label(dry_run)}")
    typer.echo(f"targets: {result.targets}")
    for tier in (*TIERS, "excluded"):
        typer.echo(f"tier {tier}: {result.tiers[tier]}")
    for kind in ("up", "down", "new", "removed"):
        typer.echo(f"tier_changed {kind}: {result.changes[kind]}")
    return True


def _run_triage(cfg: Config, limit: int | None, dry_run: bool) -> bool:
    # dry-run は API を呼ばないのでキーが無くても対象を数える
    if not dry_run and not cfg.typesafe_api_key:
        typer.echo("triage skipped: TYPESAFE_API_KEY not set")
        return True
    try:
        with ExitStack() as stack:
            store = Store.open(cfg.data_dir)
            stack.callback(store.close)
            client = None
            if not dry_run:
                client = JevClient(cfg.typesafe_api_key)
                stack.callback(client.close)
            result = triage(
                store,
                client,
                _now(),
                model=cfg.jev_model,
                min_confidence=cfg.jev_min_confidence,
                max_per_run=cfg.jev_max_per_run if limit is None else limit,
                max_chars=cfg.jev_max_chars,
                dry_run=dry_run,
            )
    except Exception as e:
        text = f"{type(e).__name__}: {e}"
        if cfg.typesafe_api_key:
            text = text.replace(cfg.typesafe_api_key, "***")
        typer.echo(f"triage failed: {text}", err=True)
        return False

    typer.echo(f"triage jev model {cfg.jev_model}{_dry_label(dry_run)}")
    typer.echo(f"targets: {result.targets}")
    typer.echo(f"limit: {result.limit}")
    if dry_run:
        typer.echo(f"first: {', '.join(result.preview) or '-'}")
        return True
    typer.echo(f"requested: {result.requested}")
    typer.echo(f"failed: {result.failed}")
    typer.echo(f"candidates: {result.candidates}")
    for kind, n in sorted(result.kinds.items()):
        typer.echo(f"kind {kind}: {n}")
    for stack_name, n in sorted(result.stacks.items()):
        typer.echo(f"stack {stack_name}: {n}")
    typer.echo(f"input_tokens: {result.input_tokens}")
    return True


def _exit_on_failure(ok: bool) -> None:
    if not ok:
        raise typer.Exit(1)


@sync_app.command("nvd")
def sync_nvd_cmd(since: SinceOption = None, dry_run: DryRunOption = False) -> None:
    """NVD CVE API から lastModified の範囲で取得する。"""
    cfg = config.load()
    _exit_on_failure(_run_nvd(cfg, _parse_since(since), dry_run))


@sync_app.command("kev")
def sync_kev_cmd(dry_run: DryRunOption = False) -> None:
    """CISA KEV カタログを取得する（ETag で条件付き GET）。"""
    _exit_on_failure(_run_kev(config.load(), dry_run))


@sync_app.command("epss")
def sync_epss_cmd(
    force: Annotated[bool, typer.Option("--force", help="当日分を取得済みでも取り直す")] = False,
    dry_run: DryRunOption = False,
) -> None:
    """対象 CVE の EPSS を FIRST API から取得する（1 日 1 回）。"""
    _exit_on_failure(_run_epss(config.load(), force, dry_run))


@sync_app.command("ghsa")
def sync_ghsa_cmd(since: SinceOption = None, dry_run: DryRunOption = False) -> None:
    """GitHub Advisory Database（npm、reviewed）から modified の範囲で取得する。"""
    cfg = config.load()
    _exit_on_failure(_run_ghsa(cfg, _parse_since(since), dry_run))


@sync_app.command("all")
def sync_all_cmd(dry_run: DryRunOption = False) -> None:
    """nvd → kev → ghsa → epss → classify → triage の順に実行する。

    失敗があっても残りを続け（classify / triage も走らせる）、最後に exit 1。
    triage は TYPESAFE_API_KEY が無ければスキップする。
    """
    cfg = config.load()
    runs = [
        lambda: _run_nvd(cfg, None, dry_run),
        lambda: _run_kev(cfg, dry_run),
        lambda: _run_ghsa(cfg, None, dry_run),
        lambda: _run_epss(cfg, False, dry_run),
        lambda: _run_classify(cfg, False, dry_run),
        lambda: _run_triage(cfg, None, dry_run),
    ]
    results = []
    for i, run in enumerate(runs):
        if i:
            typer.echo("")
        results.append(run())
    _exit_on_failure(all(results))


@app.command("classify")
def classify_cmd(
    all_subjects: Annotated[
        bool, typer.Option("--all", help="変化の有無によらず全 subject を判定し直す")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="判定して件数を出すだけで書かない")
    ] = False,
) -> None:
    """作業 DB の内容からスタックと tier（P0〜P3）をルールで判定する（shadow）。"""
    _exit_on_failure(_run_classify(config.load(), all_subjects, dry_run))


@app.command("triage")
def triage_cmd(
    limit: Annotated[
        int | None, typer.Option(min=1, help="この実行で送る CVE の上限（既定 JEV_MAX_PER_RUN）")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="対象件数と先頭 5 件の ID を出すだけで API を呼ばない")
    ] = False,
) -> None:
    """ルールで決まらない CVE を Jev（TypeSafe）で仕分けて llm_triage に記録する（shadow）。"""
    _exit_on_failure(_run_triage(config.load(), limit, dry_run))


@app.command()
def report(
    days: Annotated[int, typer.Option(min=1, help="直近何日を集計するか")] = 1,
) -> None:
    """直近 N 日の件数を表示する。"""
    cfg = config.load()
    store = Store.open(cfg.data_dir)
    try:
        rep = build_report(store, datetime.now(UTC), days)
    finally:
        store.close()
    typer.echo(format_report(rep))


@db_app.command("path")
def db_path_cmd() -> None:
    """作業 DB のパスを表示する。"""
    typer.echo(str(db_path(config.load().data_dir)))
