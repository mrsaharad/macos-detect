"""Tiny hand-layout flowchart renderer: builds SVG with exact coordinates, renders PNG via Playwright."""
import sys, html
from playwright.sync_api import sync_playwright

FONT_DIR = "/tmp/claude-0/fontpkg/node_modules/@fontsource/sarabun/files"
FS = 17          # font size px
LH = 21          # line height px


class Chart:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.items = []

    # ---------- text ----------
    def _text(self, cx, cy, text, size=FS, anchor="middle", weight=400):
        lines = text.split("\n")
        y0 = cy - (len(lines) - 1) * LH / 2
        spans = "".join(
            f'<tspan x="{cx}" y="{y0 + i * LH:.1f}">{html.escape(l)}</tspan>' for i, l in enumerate(lines)
        )
        self.items.append(
            f'<text text-anchor="{anchor}" dominant-baseline="central" font-size="{size}" font-weight="{weight}">{spans}</text>'
        )

    # ---------- shapes (return dict of anchor points) ----------
    def _anchors(self, cx, cy, w, h):
        return {"t": (cx, cy - h / 2), "b": (cx, cy + h / 2), "l": (cx - w / 2, cy), "r": (cx + w / 2, cy), "c": (cx, cy)}

    def box(self, cx, cy, w, h, text):
        self.items.append(f'<rect x="{cx-w/2}" y="{cy-h/2}" width="{w}" height="{h}" class="s"/>')
        self._text(cx, cy, text)
        return self._anchors(cx, cy, w, h)

    def oval(self, cx, cy, w, h, text):
        self.items.append(f'<rect x="{cx-w/2}" y="{cy-h/2}" width="{w}" height="{h}" rx="{h/2}" class="s"/>')
        self._text(cx, cy, text)
        return self._anchors(cx, cy, w, h)

    def diamond(self, cx, cy, w, h, text):
        pts = f"{cx},{cy-h/2} {cx+w/2},{cy} {cx},{cy+h/2} {cx-w/2},{cy}"
        self.items.append(f'<polygon points="{pts}" class="s"/>')
        self._text(cx, cy, text)
        return self._anchors(cx, cy, w, h)

    def para(self, cx, cy, w, h, text, skew=18):
        x0, x1, y0, y1 = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
        pts = f"{x0+skew},{y0} {x1+skew},{y0} {x1-skew},{y1} {x0-skew},{y1}"
        self.items.append(f'<polygon points="{pts}" class="s"/>')
        self._text(cx, cy, text)
        a = self._anchors(cx, cy, w, h)
        a["l"] = (x0, cy)
        a["r"] = (x1, cy)
        return a

    def cyl(self, cx, cy, w, h, text):
        e = 7  # ellipse ry
        x0, x1, y0, y1 = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
        self.items.append(
            f'<path d="M{x0},{y0} A{w/2},{e} 0 0,0 {x1},{y0} L{x1},{y1} A{w/2},{e} 0 0,1 {x0},{y1} Z" class="s"/>'
            f'<path d="M{x0},{y0} A{w/2},{e} 0 0,1 {x1},{y0}" class="s"/>'
        )
        self._text(cx, cy + 3, text)
        a = self._anchors(cx, cy, w, h)
        a["b"] = (cx, y1 + e)
        a["t"] = (cx, y0 - e)
        return a

    # ---------- connectors ----------
    def arrow(self, *pts, label=None, lpos=None, anchor="start", head=True):
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        marker = ' marker-end="url(#ah)"' if head else ""
        self.items.append(f'<path d="{d}" class="ln"{marker}/>')
        if label:
            self._text(lpos[0], lpos[1], label, size=15, anchor=anchor)

    def line(self, *pts):
        self.arrow(*pts, head=False)

    def dot(self, x, y):
        self.items.append(f'<circle cx="{x}" cy="{y}" r="3.2" fill="#000"/>')

    # ---------- output ----------
    def svg(self):
        return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}">
<defs><marker id="ah" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse">
<path d="M0,0 L10,5 L0,10 z" fill="#000"/></marker></defs>
<style>.s{{fill:#fff;stroke:#000;stroke-width:1.4}} .ln{{fill:none;stroke:#000;stroke-width:1.3}}
text{{font-family:'SarL','SarT',sans-serif;fill:#000}}</style>
<rect width="100%" height="100%" fill="#fff"/>
{''.join(self.items)}
</svg>"""

    def render(self, out_png, scale=3):
        page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:'SarL';font-weight:400;src:url('file://{FONT_DIR}/sarabun-latin-400-normal.woff2');}}
@font-face{{font-family:'SarL';font-weight:700;src:url('file://{FONT_DIR}/sarabun-latin-700-normal.woff2');}}
@font-face{{font-family:'SarT';font-weight:400;src:url('file://{FONT_DIR}/sarabun-thai-400-normal.woff2');}}
@font-face{{font-family:'SarT';font-weight:700;src:url('file://{FONT_DIR}/sarabun-thai-700-normal.woff2');}}
html,body{{margin:0;padding:0;background:#fff}}</style></head><body>{self.svg()}</body></html>"""
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": self.w, "height": self.h}, device_scale_factor=scale)
            pg.set_content(page)
            pg.wait_for_timeout(800)
            pg.evaluate("document.fonts.ready")
            pg.screenshot(path=out_png, clip={"x": 0, "y": 0, "width": self.w, "height": self.h})
            b.close()
