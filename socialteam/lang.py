"""Arabic support for the deterministic checks. The English-only checks silently pass Arabic text (no \\b word edges, Arabic-Indic digits are not \\d-matched by NUM in the source, first-person and hedge words differ).
These are word lists and patterns, not language understanding: a pass is never a review. They are maintained by hand, so they will miss things; every Arabic text still needs a human who reads Arabic."""
import re
AR = r"\u0621-\u064A\u0671-\u06D3"          # Arabic letters (diacritics 064B-0652 are stripped before matching)
_DIAC = re.compile(r"[\u064B-\u065F\u0670\u0640]")   # harakat, dagger alef, tatweel
_DIGITS = {**{ord(c): str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")}, **{ord(c): str(i) for i, c in enumerate("۰۱۲۳۴۵۶۷۸۹")}, ord("٫"): ".", ord("٬"): ","}
def normalize(text):
    """ASCII digits, no diacritics or tatweel, alef variants folded. For matching only, never for output."""
    t = _DIAC.sub("", str(text).translate(_DIGITS))
    return t.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا").replace("ى", "ي").replace("ة", "ه")
def is_arabic(text, share=0.3):
    letters = [c for c in str(text) if c.isalpha()]
    return bool(letters) and sum(1 for c in letters if "\u0600" <= c <= "\u06FF") / len(letters) >= share
def _w(*words):   # whole Arabic words, optionally carrying the one-letter prefixes و ف ب ل (after normalize: alef folded)
    return re.compile(rf"(?<![{AR}])(?:[وفبل])?(?:{'|'.join(words)})(?![{AR}])")
# normalized forms (alef folded, ة->ه, ى->ي)
FIRST_PERSON_AR = _w("انا", "نحن", "اختبرت", "اكتشفت", "وجدت", "جربت", "فحصت", "لاحظت", "تحققت", "قمت", "حللت", "راجعت", "اعتقد", "ارى", "ارى", "تجربتي", "اختباري", "فحصي", "اكتشافي", "رايي", "لدينا", "عندنا", "موقفنا", "اختبرنا", "اكتشفنا", "وجدنا", "فحصنا", "جربنا", "تحققنا")
HEDGE_AR = re.compile(rf"(?<![{AR}])(?:[وفبل]?ال)?استغلال[^.\n]{{0,40}}(?:غير مؤكد|غير مثبت|لم يتاكد|لم يثبت|غير موثق)|(?:قد|ربما|يحتمل|من المحتمل|لعل)[^.\n]{{0,30}}(?:استغل|يستغل|تم استغلال|استغلال)|لا يعني[^.\n]{{0,60}}استغلال|(?:غير مؤكد|لم يتاكد|لم يثبت)[^.\n]{{0,40}}(?:استغلال|استغل)")
RANSOM_AR = re.compile(r"فديه|رانسوم")
UNKNOWN_AR = re.compile(r"غير معروف|غير معلوم|مجهول|unknown", re.I)
def arabic_problems(text, ev=None):
    """Problems found in Arabic text. [] for text that is not mostly Arabic."""
    if not is_arabic(text): return []
    n = normalize(text); p = []
    if FIRST_PERSON_AR.search(n): p.append("first-person wording in Arabic (neutral third person required)")
    kev = ev is not None and getattr(ev, "source_kind", "") == "cisa-kev"
    if kev and HEDGE_AR.search(n): p.append("hedges KEV exploitation in Arabic (official CISA criteria say listing means reliable evidence of exploitation in the wild)")
    if kev and RANSOM_AR.search(n) and "unknown" in (ev.excerpt or "").lower() and not UNKNOWN_AR.search(n): p.append("ransomware use stated in Arabic without the source's Unknown status")
    return p
