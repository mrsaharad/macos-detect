"""งานเล็กก่อนส่งเล่ม: (1) จำนวนหน้าทั้งหมดในหัวบทคัดย่อ/Abstract (ตัวแปร PAGES = จำนวนหน้า PDF ทั้งเล่ม)
(2) ตารางคำย่อ: ตัดที่ไม่ได้ใช้ในเล่ม (FPR, PID/PPID) เพิ่มที่ใช้แต่ยังไม่มี แล้วเรียงตามตัวอักษร
(3) ลบหมายเหตุ [ร่าง: ตรวจชื่อเทคนิคกับ ATT&CK v19] — ตรวจกับ attack.mitre.org แล้ว 27 พ.ย. 2569: ชื่อตรงทั้ง 25 รายการ"""
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402
from thesislib import escape  # noqa: E402

PAGES = os.environ["PAGES"]
T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())

# ---------- (1) จำนวนหน้า ----------
for key in ("จำนวนหน้าทั้งหมด", "Sumethi Kiatchalermkhun"):
    i = E.doc.index(key)
    s, e = E.doc.rfind("<w:p", 0, i), E.doc.index("</w:p>", i)
    p = E.doc[s:e]
    grey = re.search(r'<w:r><w:rPr>((?:(?!</w:rPr>).)*?)<w:color w:val="808080"/>(.*?)</w:rPr><w:t xml:space="preserve">\.\.\.</w:t></w:r>',
                     p, re.S)
    assert grey, key
    rpr = (grey.group(1) + '<w:color w:val="000000"/>' + grey.group(2)).replace("<w:i/><w:iCs/>", "")
    p = p[:grey.start()] + f'<w:r><w:rPr>{rpr}</w:rPr><w:t xml:space="preserve">{PAGES}</w:t></w:r>' + p[grey.end():]
    E.doc = E.doc[:s] + p + E.doc[e:]

# ---------- (2) ตารางคำย่อ ----------
tbl = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*>ATT&amp;CK<.*?</w:tbl>", E.doc, re.S)
rows = re.findall(r"<w:tr[ >].*?</w:tr>", tbl.group(0), re.S)
head, data = rows[0], rows[1:]
tpl = data[0]


def cells(r):
    return [html.unescape("".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", c))) for c in re.findall(r"<w:tc>.*?</w:tc>", r, re.S)]


def row(a, b):
    cs = re.findall(r"<w:tc>.*?</w:tc>", tpl, re.S)
    assert all(len(re.findall(r"<w:t[ >]", c)) == 1 for c in cs)
    fill = [re.sub(r"<w:t[^>]*>[^<]*</w:t>", f'<w:t xml:space="preserve">{escape(v)}</w:t>', c) for c, v in zip(cs, (a, b))]
    return tpl[:tpl.index("<w:tc>")] + "".join(fill) + "</w:tr>"


entries = {cells(r)[0]: cells(r)[1] for r in data}
for k in ("FPR", "PID / PPID"):
    assert k in entries, k
    del entries[k]
entries.update({
    "API": "Application Programming Interface (ส่วนต่อประสานโปรแกรมประยุกต์)",
    "CI": "Confidence Interval (ช่วงความเชื่อมั่น)",
    "CSS": "Cascading Style Sheets",
    "EQL": "Event Query Language",
    "HTML": "HyperText Markup Language",
    "LotL": "Living off the Land",
    "SD": "Standard Deviation (ส่วนเบี่ยงเบนมาตรฐาน)",
    "SIEM": "Security Information and Event Management",
    "SSD": "Solid State Drive",
    "TCC": "Transparency, Consent, and Control",
})
new = tbl.group(0)[:tbl.group(0).index(head)] + head + "".join(
    row(k, entries[k]) for k in sorted(entries, key=lambda s: s.upper())) + "</w:tbl>"
E.doc = E.doc[:tbl.start()] + new + E.doc[tbl.end():]
E.put(E.para("[ร่าง: ตัดคำที่ไม่ได้ใช้ในเล่มออก"), "")

# ---------- (3) ชื่อเทคนิค ----------
E.put(E.para("[ร่าง: ตรวจชื่อเทคนิคกับ ATT&amp;CK v19]"), "")
T.write_doc(E.doc)
