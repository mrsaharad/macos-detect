"""
คลังฟังก์ชันแก้เล่ม docx (ดึงจาก insert3x.py / update_results.py ของแชท Word เดิม แต่ไม่ผูก path ของ container)
วิธีใช้:
    import thesislib as T
    T.open_doc("/path/to/unpacked")      # โฟลเดอร์ที่แตก docx ไว้
    E = T.Ed(T.read_doc())
    ... E.after("ข้อความต้นย่อหน้า", T.intro("..."))
    T.write_doc(E.doc); T.save_rels()
"""
import os
import re
import shutil
from xml.sax.saxutils import escape

from PIL import Image

U = DOC = RELS = None
rels = ""
_next_rid = [0]
_next_pic = [923300]
EMU = 914400
MAX_W, MAX_H = 5.7, 7.6


def open_doc(unpacked):
    global U, DOC, RELS, rels
    U = unpacked
    DOC = os.path.join(U, "word/document.xml")
    RELS = os.path.join(U, "word/_rels/document.xml.rels")
    rels = open(RELS, encoding="utf-8").read()
    _next_rid[0] = max(int(x) for x in re.findall(r'Id="rId(\d+)"', rels)) + 1
    ids = [int(x) for x in re.findall(r'<wp:docPr id="(\d+)"', read_doc())]
    _next_pic[0] = max(ids + [923300]) + 1


def read_doc():
    return open(DOC, encoding="utf-8").read()


def write_doc(doc):
    open(DOC, "w", encoding="utf-8").write(doc)


def save_rels():
    open(RELS, "w", encoding="utf-8").write(rels)


FONT = '<w:rFonts w:ascii="TH Sarabun New" w:hAnsi="TH Sarabun New" w:cs="TH Sarabun New"/>'
RPR = f'<w:rPr>{FONT}<w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/><w:cs/></w:rPr>'
RPR_B = f'<w:rPr>{FONT}<w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="32"/><w:szCs w:val="32"/><w:cs/></w:rPr>'
RPR_GREY = (f'<w:rPr>{FONT}<w:i/><w:iCs/><w:color w:val="808080"/><w:sz w:val="32"/><w:szCs w:val="32"/>'
            '<w:cs/><w:lang w:val="en-US"/></w:rPr>')
MONO = ('<w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="TH Sarabun New"/>'
        '<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr>')


def run(text, rpr=RPR):
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def intro(text):
    """paragraph directly under a Heading2 (first-line indent only)"""
    return (f'<w:p><w:pPr><w:spacing w:after="120"/><w:ind w:firstLine="720"/><w:jc w:val="both"/>{RPR}</w:pPr>'
            f'{run(text)}</w:p>')


def body(text):
    """paragraph under a Heading3 (left indent + first line), like 3.1.x"""
    return (f'<w:p><w:pPr><w:spacing w:after="120"/><w:ind w:left="720" w:firstLine="720"/><w:jc w:val="both"/>{RPR}</w:pPr>'
            f'{run(text)}</w:p>')


def h2(text):
    return ('<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:rPr><w:lang w:val="en-US"/></w:rPr></w:pPr>'
            f'<w:r><w:rPr><w:bCs/><w:szCs w:val="36"/><w:cs/><w:lang w:val="en-US"/></w:rPr>'
            f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')


def h3(text):
    return ('<w:p><w:pPr><w:pStyle w:val="Heading3"/><w:rPr><w:lang w:val="en-US"/></w:rPr></w:pPr>'
            f'<w:r><w:rPr><w:bCs/><w:szCs w:val="32"/><w:cs/><w:lang w:val="en-US"/></w:rPr>'
            f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')


def draft(text):
    """grey italic placeholder, same look as the existing [ร่าง: ...] paragraphs"""
    return (f'<w:p><w:pPr><w:spacing w:after="120"/><w:ind w:left="720"/><w:jc w:val="both"/>{RPR_GREY}</w:pPr>'
            f'{run("[ร่าง: " + text + "]", RPR_GREY)}</w:p>')


def caption_fig(text):
    return (f'<w:p><w:pPr><w:spacing w:after="240"/><w:jc w:val="center"/>{RPR_B}</w:pPr>{run(text, RPR_B)}</w:p>')


def caption_tbl(text):
    return (f'<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="0"/>{RPR_B}</w:pPr>{run(text, RPR_B)}</w:p>')


def after_table():
    return f'<w:p><w:pPr><w:spacing w:after="120"/>{RPR}</w:pPr></w:p>'


def cell(text, width, bold=False, center=False, header=False):
    rpr = RPR_B if bold else RPR
    jc = '<w:jc w:val="center"/>' if center else ""
    keep = "<w:keepNext/>" if header else ""
    shade = '<w:shd w:val="clear" w:color="auto" w:fill="E7E6E6"/>' if header else ""
    paras = "".join(f'<w:p><w:pPr>{keep}<w:spacing w:after="0"/>{jc}{rpr}</w:pPr>{run(line, rpr)}</w:p>'
                    for line in str(text).split("\n"))
    return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{shade}</w:tcPr>{paras}</w:tc>'


def table(headers, rows, widths, center_cols=()):
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    hdr = "".join(cell(h, w, bold=True, center=True, header=True) for h, w in zip(headers, widths))
    out = (f'<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="{sum(widths)}" w:type="dxa"/>'
           '<w:tblLayout w:type="fixed"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" '
           'w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr>'
           f'<w:tblGrid>{grid}</w:tblGrid><w:tr><w:trPr><w:tblHeader/></w:trPr>{hdr}</w:tr>')
    for r in rows:
        out += "<w:tr><w:trPr><w:cantSplit/></w:trPr>" + "".join(
            cell(v, w, center=(i in center_cols)) for i, (v, w) in enumerate(zip(r, widths))) + "</w:tr>"
    return out + "</w:tbl>"


def listing(lines):
    """1-cell shaded table holding a code listing"""
    paras = "".join(f'<w:p><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/>{MONO}</w:pPr>'
                    f'<w:r>{MONO}<w:t xml:space="preserve">{escape(l)}</w:t></w:r></w:p>' for l in lines)
    return ('<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="8100" w:type="dxa"/><w:jc w:val="center"/>'
            '<w:tblLayout w:type="fixed"/><w:tblLook w:val="04A0"/></w:tblPr><w:tblGrid><w:gridCol w:w="8100"/></w:tblGrid>'
            '<w:tr><w:trPr><w:cantSplit/></w:trPr><w:tc><w:tcPr><w:tcW w:w="8100" w:type="dxa"/>'
            '<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/><w:tcMar><w:top w:w="100" w:type="dxa"/>'
            '<w:left w:w="160" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/></w:tcMar></w:tcPr>'
            f'{paras}</w:tc></w:tr></w:tbl>')


def figure(path, name, max_h=MAX_H):
    global rels
    media = f"image_{name}.png"
    shutil.copy(path, os.path.join(U, "word/media", media))
    rid = f"rId{_next_rid[0]}"
    _next_rid[0] += 1
    rels = rels.replace("</Relationships>", f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/'
                        f'officeDocument/2006/relationships/image" Target="media/{media}"/></Relationships>')
    w, h = Image.open(path).size
    w_in = min(MAX_W, max_h * w / h)
    h_in = w_in * h / w
    cx, cy = int(w_in * EMU), int(h_in * EMU)
    pid = _next_pic[0]
    _next_pic[0] += 1
    return (f'<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60"/><w:jc w:val="center"/>{RPR}</w:pPr>'
            f'<w:r><w:rPr>{FONT}<w:noProof/><w:lang w:val="en-US"/></w:rPr><w:drawing>'
            f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
            f'<wp:effectExtent l="0" t="0" r="0" b="0"/><wp:docPr id="{pid}" name="{name}"/>'
            '<wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            f'<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{pid}" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')



PAT = r"<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>"
RPR_BODY_B = RPR_B


def ptext(m):
    return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", m.group(0)))


def rewrite_para(m, new_text):
    """keep pPr and first run's rPr, replace all runs with one run"""
    x = m.group(0)
    ppr = re.search(r"<w:pPr>.*?</w:pPr>", x, re.S).group(0)
    rpr = re.search(r"<w:r>(<w:rPr>.*?</w:rPr>)", x, re.S).group(1)
    head = x[:x.index(">") + 1]
    return f'{head}{ppr}<w:r>{rpr}<w:t xml:space="preserve">{escape(new_text)}</w:t></w:r></w:p>'


def lead(bold, text, style="body"):
    """paragraph that starts with a bold run-in heading"""
    ind = '<w:ind w:left="720" w:firstLine="720"/>' if style == "body" else '<w:ind w:firstLine="720"/>'
    return (f'<w:p><w:pPr><w:spacing w:after="120"/>{ind}<w:jc w:val="both"/>{RPR}</w:pPr>'
            f'{run(bold + " ", RPR_B)}{run(text)}</w:p>')


def note(text):
    return (f'<w:p><w:pPr><w:spacing w:after="120"/><w:jc w:val="both"/>{RPR}</w:pPr>{run(text)}</w:p>')


class Ed:
    def __init__(self, doc):
        self.doc = doc

    def one(self, pred, what):
        ms = [m for m in re.finditer(PAT, self.doc, re.S) if pred(m)]
        assert len(ms) == 1, f"{what}: found {len(ms)}"
        return ms[0]

    def para(self, prefix):
        return self.one(lambda m: not m.group(0).startswith("<w:tbl>") and ptext(m).strip().startswith(prefix), prefix)

    def put(self, m, new):
        self.doc = self.doc[:m.start()] + new + self.doc[m.end():]

    def rewrite(self, prefix, new_text):
        m = self.para(prefix)
        self.put(m, rewrite_para(m, new_text))

    def sub(self, prefix, old, new):
        m = self.para(prefix)
        t = ptext(m).replace("&amp;", "&")
        assert old in t, f"{prefix}: '{old}' not found"
        self.put(m, rewrite_para(m, t.replace(old, new)))

    def replace(self, prefix, xml):
        self.put(self.para(prefix), xml)

    def after(self, prefix, xml):
        m = self.para(prefix)
        self.doc = self.doc[:m.end()] + xml + self.doc[m.end():]

    def table_after(self, caption, xml):
        m = self.para(caption)
        i = self.doc.index("<w:tbl>", m.end())
        j = self.doc.index("</w:tbl>", i) + len("</w:tbl>")
        self.doc = self.doc[:i] + xml + self.doc[j:]

    def table_with(self, text, xml):
        m = self.one(lambda m: m.group(0).startswith("<w:tbl>") and text in ptext(m), text)
        self.put(m, xml)


def pct(a, b):
    return f"{a}/{b} ({a / b * 100:.1f}%)"


