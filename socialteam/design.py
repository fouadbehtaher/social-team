import textwrap, os
from PIL import Image, ImageDraw, ImageFont, features
from . import lang
B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"; R = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
AB = "/usr/share/fonts/truetype/noto/NotoKufiArabic-Bold.ttf"; AR_ = "/usr/share/fonts/truetype/noto/NotoKufiArabic-Regular.ttf"   # DejaVu also has Arabic glyphs, used when Noto Kufi is absent
def _covers(p, text):
    from fontTools.ttLib import TTFont
    cm = TTFont(p).getBestCmap(); return all(ord(c) in cm for c in text if not c.isspace())
def _font(path, size, arabic, text=""):
    """Noto Kufi has no Latin punctuation (draws tofu for ':' and '.'), so it is used only when it covers every character of the text; otherwise DejaVu, which has both Arabic and Latin glyphs."""
    if arabic:
        k = AB if path == B else AR_
        try:
            if os.path.exists(k) and _covers(k, text): return ImageFont.truetype(k, size)
        except Exception: pass
    return ImageFont.truetype(path, size)
def _wrap(t, w, n):
    lines = textwrap.wrap(t, w)
    if len(lines) > n: lines = lines[:n]; lines[-1] = textwrap.shorten(lines[-1] + ' ...', w, placeholder='...')   # whole-word cut
    return lines

def card(path, platform, ev, brief=None):
    """Card shows only verified facts: the source's own title, domain and date. Arabic headline/subline are drawn right-to-left with text shaping (needs Pillow's raqm layout, else the card refuses rather than draw broken letters)."""
    head = (brief or {}).get('headline') or ev.title; sub = (brief or {}).get('subline') or ""
    ar = lang.is_arabic(head) or lang.is_arabic(sub)
    if ar and not features.check("raqm"): raise RuntimeError("Arabic card needs Pillow with raqm (libraqm); refusing to draw unshaped Arabic")
    f1, f2 = _font(B, 52, ar, head), _font(R, 30, ar, sub); fl = ImageFont.truetype(R, 30)
    im = Image.new("RGB", (1080, 1080), (14, 20, 36)); d = ImageDraw.Draw(im)
    d.rectangle([0, 0, 1080, 14], fill=(0, 200, 150))
    d.text((70, 80), platform.upper() + "  |  DRAFT, NOT PUBLISHED", fill=(0, 200, 150), font=fl)
    def line(y, text, font, fill):
        if lang.is_arabic(text): d.text((1010, y), text, fill=fill, font=font, anchor="ra", direction="rtl", language="ar")
        else: d.text((70, y), text, fill=fill, font=font)
    y = 190
    for l in _wrap(head, 26 if not ar else 22, 8): line(y, l, f1, "white"); y += 68
    if sub:
        y += 20
        for l in textwrap.wrap(sub, 40 if not ar else 32)[:3]: line(y, l, f2, (190, 200, 215)); y += 44 if ar else 40
    d.text((70, 900), f"Source: {ev.domain}", fill=(190, 200, 215), font=fl)
    d.text((70, 945), f"Published: {ev.published or 'date not stated on page'}", fill=(190, 200, 215), font=fl)
    d.text((70, 990), os.environ.get("ST_BYLINE", "Security"), fill=(120, 130, 150), font=fl)
    os.makedirs(os.path.dirname(path), exist_ok=True); im.save(path); return path
