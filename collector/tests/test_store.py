import stat

from vuln_signal.store import Store


def test_new_db_permissions_and_version(tmp_path):
    data_dir = tmp_path / "a" / "data"
    s = Store.open(data_dir)
    try:
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
        assert s.user_version() == 1
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
        assert s.user_version() == 1
        assert s.get_sync_state("nvd")["cursor"] == "2099-01-01T00:00:00Z"
        tables = {
            r[0] for r in s.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {"sync_state", "cve", "cve_event"} <= tables
    finally:
        s.close()
