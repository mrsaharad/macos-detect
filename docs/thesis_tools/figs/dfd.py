"""Extra shapes for DFD / ER / site map on top of the flowchart renderer."""
import html
import sys

sys.path.insert(0, "/tmp/claude-0/fig")
from flow import Chart, FONT_DIR, LH  # noqa: E402


class Diagram(Chart):
    def label(self, x, y, text, size=14, anchor="middle"):
        lines = text.split("\n")
        y0 = y - (len(lines) - 1) * (size + 3) / 2
        spans = "".join(f'<tspan x="{x}" y="{y0 + i * (size + 3):.1f}">{html.escape(l)}</tspan>'
                        for i, l in enumerate(lines))
        self.items.append(f'<text class="lbl" text-anchor="{anchor}" dominant-baseline="central" '
                          f'font-size="{size}">{spans}</text>')

    def proc(self, cx, cy, w, h, num, text):
        """Gane-Sarson process: rounded box, number band on top"""
        x0, y0 = cx - w / 2, cy - h / 2
        self.items.append(f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="10" class="s"/>')
        self.items.append(f'<line x1="{x0}" y1="{y0 + 26}" x2="{x0 + w}" y2="{y0 + 26}" class="ln"/>')
        self._text(cx, y0 + 13, num, size=15, weight=700)
        self._text(cx, y0 + 26 + (h - 26) / 2, text, size=16)
        return self._anchors(cx, cy, w, h)

    def store(self, cx, cy, w, h, sid, text, dup=False):
        """Gane-Sarson data store: open on the right"""
        x0, y0, x1, y1 = cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2
        self.items.append(f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" fill="#fff" stroke="none"/>')
        self.items.append(f'<path d="M{x1},{y0} L{x0},{y0} L{x0},{y1} L{x1},{y1}" class="ln"/>')
        self.items.append(f'<line x1="{x0 + 44}" y1="{y0}" x2="{x0 + 44}" y2="{y1}" class="ln"/>')
        if dup:
            self.items.append(f'<line x1="{x0 + 8}" y1="{y0}" x2="{x0 + 8}" y2="{y1}" class="ln"/>')
        self._text(x0 + (26 if dup else 22), cy, sid, size=15, weight=700)
        self._text(x0 + 44 + (w - 44) / 2, cy, text, size=16)
        return self._anchors(cx, cy, w, h)

    def ext(self, cx, cy, w, h, text):
        """External entity: square box with offset shadow"""
        x0, y0 = cx - w / 2, cy - h / 2
        self.items.append(f'<rect x="{x0 + 4}" y="{y0 + 4}" width="{w}" height="{h}" fill="#000"/>')
        self.items.append(f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" class="s"/>')
        self._text(cx, cy, text, size=16, weight=600)
        return self._anchors(cx, cy, w, h)

    def entity(self, x, y, w, title, rows, dashed=False, rh=27, kw=40):
        """ER entity: header + attribute rows; rows = [(key, name, type)]; returns y of each row centre"""
        h = 34 + rh * len(rows)
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        self.items.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff" stroke="#000" stroke-width="1.4"{dash}/>')
        self.items.append(f'<rect x="{x}" y="{y}" width="{w}" height="34" fill="#e9e9e9" stroke="#000" stroke-width="1.4"{dash}/>')
        self._text(x + w / 2, y + 17, title, size=16, weight=700)
        ys = {}
        for i, (key, name, typ) in enumerate(rows):
            cy = y + 34 + rh * i + rh / 2
            ys[name] = cy
            if key:
                self._text(x + 10, cy, key, size=12, anchor="start", weight=700)
            self._text(x + kw + 6, cy, name, size=15, anchor="start", weight=700 if "PK" in key else 400)
            self._text(x + w - 10, cy, typ, size=13, anchor="end")
        self.items.append(f'<line x1="{x + kw}" y1="{y + 34}" x2="{x + kw}" y2="{y + h}" stroke="#000" stroke-width="0.8"{dash}/>')
        return ys, h

    # crow's foot end markers drawn at point (x,y) for a line arriving horizontally from direction d (+1 = from left)
    def end_one(self, x, y, d):
        for off in (10, 16):
            xx = x - d * off
            self.items.append(f'<line x1="{xx}" y1="{y - 8}" x2="{xx}" y2="{y + 8}" class="ln"/>')

    def end_many_opt(self, x, y, d):
        self.items.append(f'<line x1="{x - d * 14}" y1="{y}" x2="{x}" y2="{y - 9}" class="ln"/>')
        self.items.append(f'<line x1="{x - d * 14}" y1="{y}" x2="{x}" y2="{y + 9}" class="ln"/>')
        self.items.append(f'<circle cx="{x - d * 22}" cy="{y}" r="5" fill="#fff" stroke="#000" stroke-width="1.3"/>')

    def end_one_opt(self, x, y, d):
        xx = x - d * 10
        self.items.append(f'<line x1="{xx}" y1="{y - 8}" x2="{xx}" y2="{y + 8}" class="ln"/>')
        self.items.append(f'<circle cx="{x - d * 20}" cy="{y}" r="5" fill="#fff" stroke="#000" stroke-width="1.3"/>')

    def svg(self):
        s = super().svg()
        return s.replace("</style>", " .lbl{paint-order:stroke;stroke:#fff;stroke-width:5px;stroke-linejoin:round}</style>")
