import sqlite3
import stat

from vuln_signal.store import DB_FILENAME, MIGRATIONS, SCHEMA_VERSION, Store


def test_new_db_permissions_and_version(tmp_path):
    data_dir = tmp_path / "a" / "data"
    s = Store.open(data_dir)
    try:
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
        assert s.user_version() == SCHEMA_VERSION == 2
        assert s.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert s.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        s.close()


def test_reopen_keeps_data(tmp_path):
    s = Store.open(tmp_path)
    s.mark_sync_ok("nvd", "2099-01-01T00:00:00Z")
    s.close()

    s = Store.open(tmp_path)
    try:
        assert s.user_version() == SCHEMA_VERSION == 2
        assert s.get_sync_state("nvd")["cursor"] == "2099-01-01T00:00:00Z"
        tables = {
            r[0] for r in s.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {"sync_state", "cve", "cve_event", "kev", "epss", "ghsa"} <= tables
    finally:
        s.close()


def _make_v1_db(data_dir):
    data_dir.mkdir(parents=True)
    conn = sqlite3.connect(data_dir / DB_FILENAME, autocommit=True)
    for stmt in MIGRATIONS[0].split(";"):
        if stmt.strip():
            conn.execute(stmt)
    conn.execute("PRAGMA user_version = 1")
    conn.execute("INSERT INTO cve (id) VALUES ('CVE-2099-0001')")
    conn.execute("INSERT INTO sync_state (source, cursor) VALUES ('nvd', '2099-01-01T00:00:00Z')")
    rows = [
        (3, "CVE-2099-0001", "2099-01-01T00:00:00Z", "first_seen", None, "x", "nvd"),
        (7, "CVE-2099-0001", "2099-01-02T00:00:00Z", "status_changed", "a", "b", "nvd"),
    ]
    conn.executemany("INSERT INTO cve_event VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    conn.close()
    return rows


def test_migrate_v1_to_v2_keeps_events_and_drops_fk(tmp_path):
    rows = _make_v1_db(tmp_path / "data")
    s = Store.open(tmp_path / "data")
    try:
        assert s.user_version() == 2
        assert [tuple(r) for r in s.conn.execute("SELECT * FROM cve_event ORDER BY id")] == rows
        assert s.conn.execute("PRAGMA foreign_key_list(cve_event)").fetchall() == []
        indexes = {r["name"] for r in s.conn.execute("PRAGMA index_list(cve_event)")}
        assert {"cve_event_cve_observed", "cve_event_observed"} <= indexes
        # NVD に無い CVE や GHSA ID でもイベントを積める
        s.add_event(
            "GHSA-xxxx-xxxx-xxxx", "2099-01-03T00:00:00Z", "ghsa_first_seen", None, "g", "ghsa"
        )
        s.add_event("CVE-2099-9999", "2099-01-03T00:00:00Z", "kev_added", None, "d", "kev")
        # AUTOINCREMENT の続きから採番される
        ids = [r[0] for r in s.conn.execute("SELECT id FROM cve_event ORDER BY id")]
        assert ids == [3, 7, 8, 9]
        state = s.get_sync_state("nvd")
        assert state["cursor"] == "2099-01-01T00:00:00Z" and state["etag"] is None
    finally:
        s.close()


def test_mark_sync_ok_with_cursor_and_etag(store):
    store.set_sync_etag("kev", '"abc"')
    store.mark_sync_ok("kev", "2099-01-01T00:00:00Z", cursor="2099.01.01")
    state = store.get_sync_state("kev")
    assert state["cursor"] == "2099.01.01"
    assert state["last_ok_at"] == "2099-01-01T00:00:00Z"
    assert state["etag"] == '"abc"'
    store.set_sync_etag("kev", None)
    assert store.get_sync_state("kev")["etag"] is None
