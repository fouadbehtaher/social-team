"""Seeds ONE clearly labeled TEST item to exercise review -> approve -> export. Text is fixed here, no model, no network, no real source claim."""
import json, time
from .models import Evidence, key
from . import design, review
TEXT = "TEST ITEM. This sentence is fixed fixture text used to check the review and approval path. It says nothing about any real vulnerability or source."
TEXT_AR = "عنصر تجريبي. هذا النص ثابت ويُستخدم فقط لفحص مسار المراجعة والموافقة بالعربية. لا يتحدث عن أي ثغرة أو مصدر حقيقي."
def seed(store, out_dir, arabic=False):
    if store.db.execute("SELECT COUNT(*) FROM items WHERE meta IS NULL OR meta NOT LIKE '%test_fixture%'").fetchone()[0]:
        raise SystemExit("refusing: this database already holds real items; use an empty ST_OUT for the fixture")
    id_ = key("test-fixture", "linkedin")
    ev = Evidence(url="https://example.invalid/test", final_url="https://example.invalid/test", domain="example.invalid (TEST, not a source)", title="TEST ITEM: review path check" if not arabic else "عنصر تجريبي: فحص مسار المراجعة",
                  published=None, excerpt=TEXT_AR if arabic else TEXT, fetched_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), http_status=0, primary=False)
    store.add_lead(id_, "linkedin", ev.title, ev.url, json.dumps({"test_fixture": True}))
    p = design.card(f"{out_dir}/cards/{id_}.png", "linkedin", ev, ({"headline": "عنصر تجريبي: ليس منشورًا حقيقيًا", "subline": "نص ثابت لفحص المراجعة والموافقة. ليس ناتج نموذج."} if arabic else {"headline": "TEST ITEM: not a real post", "subline": "Fixture used to check review and approval. Not model output."}))
    d = {"platform": "linkedin", "text": TEXT_AR if arabic else TEXT, "provider": "TEST-FIXTURE (no model)", "cost_usd": 0.0, "problems": []}
    store.db.execute("UPDATE items SET state='PENDING_REVIEW', evidence=?, draft=?, image=? WHERE id=?", (json.dumps(ev.__dict__), json.dumps(d), p, id_)); store.db.commit()
    store.event("fixture", id_, note="test fixture seeded"); review.stamp(store, id_); review.render(store, out_dir); return id_
