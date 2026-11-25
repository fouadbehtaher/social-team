import textwrap, os
from PIL import Image, ImageDraw, ImageFont
B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"; R = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
def _wrap(t, w, n):
    lines = textwrap.wrap(t, w)
    if len(lines) > n: lines = lines[:n]; lines[-1] = textwrap.shorten(lines[-1] + ' ...', w, placeholder='...')   # whole-word cut
    return lines

def card(path, platform, ev, brief=None):
    """Card shows only verified facts: the source's own title, domain and date."""
    f1, f2 = ImageFont.truetype(B, 52), ImageFont.truetype(R, 30)
    im = Image.new("RGB", (1080, 1080), (14, 20, 36)); d = ImageDraw.Draw(im)
    d.rectangle([0, 0, 1080, 14], fill=(0, 200, 150))
    d.text((70, 80), platform.upper() + "  |  DRAFT, NOT PUBLISHED", fill=(0, 200, 150), font=f2)
    y = 190
    for line in _wrap((brief or {}).get('headline') or ev.title, 26, 8): d.text((70, y), line, fill="white", font=f1); y += 68
    if brief and brief.get('subline'):
        y += 20
        for line in textwrap.wrap(brief['subline'], 40)[:3]: d.text((70, y), line, fill=(190, 200, 215), font=f2); y += 40
    d.text((70, 900), f"Source: {ev.domain}", fill=(190, 200, 215), font=f2)
    d.text((70, 945), f"Published: {ev.published or 'date not stated on page'}", fill=(190, 200, 215), font=f2)
    d.text((70, 990), os.environ.get("ST_BYLINE", "Security"), fill=(120, 130, 150), font=f2)
    os.makedirs(os.path.dirname(path), exist_ok=True); im.save(path); return path
