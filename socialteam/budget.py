"""Local fail-closed spend ledger. This is OUR cap, not a provider limit. Provider-side hard limit = prepaid credits balance with invoiced limit $0 (docs.x.ai/console/billing)."""
import sqlite3, time
class BudgetExceeded(Exception): pass
SQL = "CREATE TABLE IF NOT EXISTS reservations(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, provider TEXT, reserved REAL, actual REAL, status TEXT)"
class Budget:
    def __init__(self, path, cap_usd_per_day, window=86400):
        self.path, self.cap, self.window = path, cap_usd_per_day, window
        c = self._c(); c.execute(SQL); c.commit(); c.close()
    def _c(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None); return c
    def reserve(self, provider, worst_case_usd):
        """Atomic across processes/threads: BEGIN IMMEDIATE takes the write lock before reading the total."""
        c = self._c()
        try:
            c.execute("BEGIN IMMEDIATE")
            used = c.execute("SELECT COALESCE(SUM(CASE WHEN status='settled' THEN actual ELSE reserved END),0) FROM reservations WHERE ts>=?", (time.time() - self.window,)).fetchone()[0]
            if used + worst_case_usd > self.cap + 1e-12:
                c.execute("ROLLBACK"); raise BudgetExceeded(f"reserve ${worst_case_usd:.4f} would exceed cap ${self.cap} (used/held ${used:.4f})")
            cur = c.execute("INSERT INTO reservations(ts,provider,reserved,status) VALUES(?,?,?,'held')", (time.time(), provider, worst_case_usd))
            c.execute("COMMIT"); return cur.lastrowid
        finally: c.close()
    def settle(self, rid, actual_usd):
        c = self._c(); c.execute("UPDATE reservations SET actual=?, status='settled' WHERE id=?", (min(actual_usd, 1e9), rid)); c.close()
    # unknown usage / error after send: do NOT release; reservation stays held at worst case (fail closed)
    def used(self):
        c = self._c(); v = c.execute("SELECT COALESCE(SUM(CASE WHEN status='settled' THEN actual ELSE reserved END),0) FROM reservations WHERE ts>=?", (time.time() - self.window,)).fetchone()[0]; c.close(); return v
