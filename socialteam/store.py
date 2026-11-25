import sqlite3, json, time
from .models import TRANSITIONS

SCHEMA = """
CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY, platform TEXT, state TEXT, lead_title TEXT, lead_url TEXT,
  evidence TEXT, draft TEXT, image TEXT, reviewer_note TEXT, created REAL, updated REAL, attempts INT DEFAULT 0, content_hash TEXT, approved_hash TEXT, meta TEXT, roles TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, item_id TEXT, node TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS spend(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, provider TEXT, usd REAL);
CREATE TABLE IF NOT EXISTS metrics(post_id TEXT, platform TEXT, date TEXT, impressions INT, engagements INT, UNIQUE(post_id, platform, date));
"""
class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False); self.db.row_factory = sqlite3.Row; self.db.executescript(SCHEMA)
    def event(self, node, item_id=None, **detail):
        self.db.execute("INSERT INTO events(ts,item_id,node,detail) VALUES(?,?,?,?)", (time.time(), item_id, node, json.dumps(detail))); self.db.commit()
    def add_lead(self, id_, platform, title, url, meta=None):
        cur = self.db.execute("INSERT OR IGNORE INTO items(id,platform,state,lead_title,lead_url,created,updated,meta) VALUES(?,?,?,?,?,?,?,?)",
                              (id_, platform, "LEAD", title, url, time.time(), time.time(), meta)); self.db.commit(); return cur.rowcount == 1  # False = duplicate (idempotent)
    def get(self, id_): return self.db.execute("SELECT * FROM items WHERE id=?", (id_,)).fetchone()
    def by_state(self, state): return self.db.execute("SELECT * FROM items WHERE state=? ORDER BY created", (state,)).fetchall()
    def move(self, id_, new, **cols):
        cur = self.get(id_)["state"]
        if new not in TRANSITIONS.get(cur, set()): raise ValueError(f"illegal transition {cur}->{new}")
        sets = ",".join(f"{k}=?" for k in cols); vals = list(cols.values())
        self.db.execute(f"UPDATE items SET state=?,updated=?{',' + sets if sets else ''} WHERE id=?", [new, time.time(), *vals, id_]); self.db.commit()
        self.event("transition", id_, frm=cur, to=new)
    def add_spend(self, provider, usd): self.db.execute("INSERT INTO spend(ts,provider,usd) VALUES(?,?,?)", (time.time(), provider, usd)); self.db.commit()
    def spent_since(self, ts): return self.db.execute("SELECT COALESCE(SUM(usd),0) FROM spend WHERE ts>=?", (ts,)).fetchone()[0]
