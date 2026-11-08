"""コマンドライン: vuln-signal sync nvd / report / db path。"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

import typer

from vuln_signal import config
from vuln_signal.report import build_report, format_report
from vuln_signal.sources.nvd import NvdClient
from vuln_signal.store import Store, db_path, iso, parse_iso
from vuln_signal.sync import sync_nvd

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


@sync_app.command("nvd")
def sync_nvd_cmd(
    since: Annotated[
        str | None, typer.Option(help="開始時刻（UTC、例 2026-11-06T00:00:00Z）")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="取得と差分計算だけして書かない")
    ] = False,
) -> None:
    """NVD CVE API から lastModified の範囲で取得する。"""
    cfg = config.load()
    since_dt = _parse_since(since)
    now = datetime.now(UTC).replace(microsecond=0)
    store = Store.open(cfg.data_dir)
    client = NvdClient(cfg.nvd_api_key)
    try:
        result = sync_nvd(
            store,
            client,
            now,
            since_dt,
            lookback_hours=cfg.nvd_initial_lookback_hours,
            dry_run=dry_run,
        )
    except Exception as e:
        typer.echo(f"sync nvd failed: {client.redact(f'{type(e).__name__}: {e}')}", err=True)
        raise typer.Exit(1) from None
    finally:
        client.close()
        store.close()

    label = " (dry-run, not written)" if dry_run else ""
    typer.echo(f"nvd {iso(result.start)} .. {iso(result.end)}{label}")
    typer.echo(f"requests: {client.request_count}")
    typer.echo(f"fetched: {result.fetched}")
    typer.echo(f"new: {result.new}")
    for kind, n in sorted(result.events.items()):
        typer.echo(f"event {kind}: {n}")


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
