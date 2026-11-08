"""作業 DB（SQLite）。

スキーマは PRAGMA user_version で版管理し、open 時に未適用の版を順に当てる。
時刻はすべて UTC の ISO 8601（2026-11-07T01:23:45Z）の文字列で持つ。
"""

from __future__ import annotations

import gzip
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_signal.sources.nvd import CveRecord

DB_FILENAME = "work.sqlite3"

# 版ごとの DDL。添字 + 1 が user_version
MIGRATIONS: list[str] = [
    """
    CREATE TABLE sync_state (
        source TEXT PRIMARY KEY,
        cursor TEXT,
        last_run_at TEXT,
        last_ok_at TEXT,
        last_error TEXT
    );
    CREATE TABLE cve (
        id TEXT PRIMARY KEY,
        published TEXT,
        last_modified TEXT,
        vuln_status TEXT,
        source_identifier TEXT,
        description_en TEXT,
        cvss_v31_score REAL,
        cvss_v31_vector TEXT,
        cvss_v31_severity TEXT,
        cvss_v40_score REAL,
        cvss_v40_vector TEXT,
        cvss_v40_severity TEXT,
        cwe_ids TEXT,       -- JSON 配列
        cpe_criteria TEXT,  -- JSON 配列: vulnerable=true の criteria 文字列
        raw_gz BLOB,        -- NVD の vulnerabilities[].cve を JSON にして gzip
        fetched_at TEXT
    );
    CREATE TABLE cve_event (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL REFERENCES cve(id),
        observed_at TEXT NOT NULL,
        kind TEXT NOT NULL,
        before TEXT,
        after TEXT,
        source TEXT NOT NULL
    );
    CREATE INDEX cve_event_cve_observed ON cve_event (cve_id, observed_at);
    CREATE INDEX cve_event_observed ON cve_event (observed_at);
    """,
]
SCHEMA_VERSION = len(MIGRATIONS)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def db_path(data_dir: Path) -> Path:
    return data_dir / DB_FILENAME


class Store:
    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self.conn = conn
        self.path = path

    @classmethod
    def open(cls, data_dir: Path) -> Store:
        if not data_dir.exists():
            data_dir.mkdir(mode=0o700, parents=True)
        path = db_path(data_dir)
        created = not path.exists()
        conn = sqlite3.connect(path, autocommit=True)
        conn.row_factory = sqlite3.Row
        if created:
            os.chmod(path, 0o600)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        store = cls(conn, path)
        store._migrate()
        return store

    def close(self) -> None:
        self.conn.close()

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        for v in range(version, SCHEMA_VERSION):
            with self.transaction():
                for stmt in MIGRATIONS[v].split(";"):
                    if stmt.strip():
                        self.conn.execute(stmt)
                self.conn.execute(f"PRAGMA user_version = {v + 1}")

    def user_version(self) -> int:
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # --- sync_state ---

    def get_sync_state(self, source: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM sync_state WHERE source = ?", (source,)).fetchone()

    def list_sync_state(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM sync_state ORDER BY source").fetchall()

    def mark_sync_ok(self, source: str, now: str) -> None:
        self.conn.execute(
            """
            INSERT INTO sync_state (source, cursor, last_run_at, last_ok_at, last_error)
            VALUES (?, ?, ?, ?, NULL)
            ON CONFLICT (source) DO UPDATE SET
                cursor = excluded.cursor,
                last_run_at = excluded.last_run_at,
                last_ok_at = excluded.last_ok_at,
                last_error = NULL
            """,
            (source, now, now, now),
        )

    def mark_sync_error(self, source: str, now: str, error: str) -> None:
        self.conn.execute(
            """
            INSERT INTO sync_state (source, last_run_at, last_error) VALUES (?, ?, ?)
            ON CONFLICT (source) DO UPDATE SET
                last_run_at = excluded.last_run_at,
                last_error = excluded.last_error
            """,
            (source, now, error),
        )

    # --- cve ---

    def get_cve(self, cve_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM cve WHERE id = ?", (cve_id,)).fetchone()

    def upsert_cve(self, rec: CveRecord, fetched_at: str) -> None:
        raw_gz = gzip.compress(json.dumps(rec.raw, ensure_ascii=False).encode("utf-8"))
        row: dict[str, Any] = {
            "id": rec.id,
            "published": rec.published,
            "last_modified": rec.last_modified,
            "vuln_status": rec.vuln_status,
            "source_identifier": rec.source_identifier,
            "description_en": rec.description_en,
            "cvss_v31_score": rec.cvss_v31_score,
            "cvss_v31_vector": rec.cvss_v31_vector,
            "cvss_v31_severity": rec.cvss_v31_severity,
            "cvss_v40_score": rec.cvss_v40_score,
            "cvss_v40_vector": rec.cvss_v40_vector,
            "cvss_v40_severity": rec.cvss_v40_severity,
            "cwe_ids": json.dumps(rec.cwe_ids),
            "cpe_criteria": json.dumps(rec.cpe_criteria),
            "raw_gz": raw_gz,
            "fetched_at": fetched_at,
        }
        cols = ", ".join(row)
        params = ", ".join(f":{c}" for c in row)
        updates = ", ".join(f"{c} = excluded.{c}" for c in row if c != "id")
        self.conn.execute(
            f"INSERT INTO cve ({cols}) VALUES ({params}) ON CONFLICT (id) DO UPDATE SET {updates}",
            row,
        )

    def add_event(
        self,
        cve_id: str,
        observed_at: str,
        kind: str,
        before: str | None,
        after: str | None,
        source: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO cve_event (cve_id, observed_at, kind, before, after, source) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cve_id, observed_at, kind, before, after, source),
        )
