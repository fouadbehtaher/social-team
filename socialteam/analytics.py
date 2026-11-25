import csv, io
REQ = ["post_id", "platform", "date", "impressions", "engagements"]
def import_csv(store, text):
    rd = csv.DictReader(io.StringIO(text)); miss = [c for c in REQ if c not in (rd.fieldnames or [])]
    if miss: raise ValueError(f"missing columns: {miss}")
    ok, bad = 0, []
    for i, r in enumerate(rd, 2):
        try:
            im, en = int(r["impressions"]), int(r["engagements"])
            if im < 0 or en < 0 or en > im: raise ValueError("engagements>impressions or negative")
            store.db.execute("INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?)", (r["post_id"], r["platform"].lower(), r["date"], im, en)); ok += 1
        except Exception as e: bad.append((i, str(e)))
    store.db.commit(); return ok, bad
def report(store, min_posts=5):
    out = {}
    for r in store.db.execute("SELECT platform, COUNT(DISTINCT post_id) n, SUM(impressions) i, SUM(engagements) e FROM metrics GROUP BY platform"):
        out[r["platform"]] = {"posts": r["n"], "impressions": r["i"], "engagement_rate": round(r["e"] / r["i"], 4) if r["i"] else None,
                              "verdict": "enough data to compare" if r["n"] >= min_posts else f"too few posts (<{min_posts}), no conclusion"}
    return out or {"status": "NO_DATA"}
