"""แก้จากการตรวจเล่มรอบที่ 2 (27 พ.ย. 2569)
A1 "ATT&amp;CK" พิมพ์ตรงตัว (3.1.3, 3.1.5)      A2 tab กลางประโยค (1.1 x2, 2.1.1)
A3 ช่องว่างแทรกกลางวลี / เว้นวรรคซ้อน               A4 ประโยคติดกันไม่เว้นวรรค (2.1.1, 2.1.2)
B5 ย้ายประโยค "ดำเนินงานจริง" ใน 1.5               B6 2.2.3 บอกว่ารุ่นที่ 2 เก็บเหตุการณ์เพิ่ม
B7 5.1 ข้อ 4 และ 5.2 อ้างรุ่นที่ 2                 B8 4.3 "T1059.006 13 test"
B9 แยกหมายเหตุใต้ตารางที่ 4.15                      B10 คำย่อ TCP, UDP, ISO
B11 รูปที่ 2.5 ตัดพื้นหลังเบลอออก (figs/out/fig25_eslogger_cropped.png)"""
import html
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402
from thesislib import escape  # noqa: E402

FIGS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "figs", "out"))
T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())
CODE = "ตารางภาคผนวกที่ ค.1 ไฟล์โปรแกรมของระบบ"     # ห้ามแตะโค้ดในภาคผนวก ค


def head_tail():
    k = E.doc.index(CODE)
    return E.doc[:k], E.doc[k:]


def fix(old, new, n=1):
    """แทนข้อความในเนื้อหา: ถ้าอยู่ใน run เดียวแทนใน XML ตรง ๆ ไม่งั้นเขียนย่อหน้านั้นใหม่"""
    head, tail = head_tail()
    xo, xn = escape(old), escape(new)
    if head.count(xo) == n:
        E.doc = head.replace(xo, xn) + tail
        return
    ms = [m for m in re.finditer(T.PAT, head, re.S)
          if not m.group(0).startswith("<w:tbl>") and old in html.unescape(T.ptext(m))]
    assert len(ms) == n == 1, f"{old!r}: พบ {len(ms)} ย่อหน้า"
    m = ms[0]
    E.put(m, T.rewrite_para(m, html.unescape(T.ptext(m)).replace(old, new)))


# ---------- A1 ----------
head, tail = head_tail()
assert head.count("ATT&amp;amp;CK") == 2, head.count("ATT&amp;amp;CK")
E.doc = head.replace("ATT&amp;amp;CK", "ATT&amp;CK") + tail

# ---------- A2: tab กลางประโยค ----------
for prefix in ("ในอดีต การพัฒนาโปรแกรมที่รับข้อมูลพฤติกรรม", "โครงงานนี้คาดว่าจะสามารถพัฒนา",
               "นอกจากนี้ MITRE ATT&amp;CK ยังแบ่ง Matrix"):
    m = E.para(prefix)
    g = m.group(0)
    assert g.count("<w:tab/>") == 1, (prefix, g.count("<w:tab/>"))
    E.put(m, g.replace("<w:tab/>", ""))

# ---------- A3: ช่องว่างผิดที่ ----------
for old, new in [
    ("กฎที่เขียนจากข้อมูล ชุด dev", "กฎที่เขียนจากข้อมูลชุด dev"),
    ("ผ่านเกณฑ์ความเสถียรต่อเนื่อง ไม่น้อยกว่า", "ผ่านเกณฑ์ความเสถียรต่อเนื่องไม่น้อยกว่า"),
    ("เก็บบรรทัดที่รอ ประมวลผล", "เก็บบรรทัดที่รอประมวลผล"),
    ("ซอฟต์แวร์ที่ ทำงานตามปกติ", "ซอฟต์แวร์ที่ทำงานตามปกติ"),
    ("จนบันทึก ลงฐานข้อมูล", "จนบันทึกลงฐานข้อมูล"),
    ("40 ครั้ง ต่อโปรเซส", "40 ครั้งต่อโปรเซส"),
    ("ได้สูงสุด ประมาณ 10,600", "ได้สูงสุดประมาณ 10,600"),
    ("ที่ช้า ประมาณ 3 นาที", "ที่ช้าประมาณ 3 นาที"),
    ("ประมวลผลเหตุการณ์ จากโปรเซสแรกก่อน", "ประมวลผลเหตุการณ์จากโปรเซสแรกก่อน"),
    ("ตามนาฬิการวม ประมาณ 26.7", "ตามนาฬิการวมประมาณ 26.7"),
    ("ตั้งแต่ต้นทาง ด้วยตัวรับเหตุการณ์", "ตั้งแต่ต้นทางด้วยตัวรับเหตุการณ์"),
    ("SQLite  เป็นระบบจัดการ", "SQLite เป็นระบบจัดการ"),
    ("ไม่ได้รัน Atomic Test ซ้ำ  ค่าในวงเล็บ", "ไม่ได้รัน Atomic Test ซ้ำ ค่าในวงเล็บ"),
]:
    fix(old, new)

# ---------- A4: ประโยคติดกัน ----------
fix("ตรวจจับกิจกรรมที่ผิดปกติระบบ EDR", "ตรวจจับกิจกรรมที่ผิดปกติ ระบบ EDR")
fix("อย่างมีนัยสำคัญทำให้สามารถ", "อย่างมีนัยสำคัญ ทำให้สามารถ")

# ---------- B5: 1.5 ----------
ACTUAL = ("ในการดำเนินงานจริง การพัฒนาและทดสอบระบบทั้งสองรุ่นเสร็จในเดือนพฤศจิกายน 2569 ซึ่งเร็วกว่าแผน "
          "ผลการทดสอบในบทที่ 4 จึงเป็นผลจากวันที่ 22–27 พฤศจิกายน 2569")
fix(" " + ACTUAL, "")
fix("แผนการดำเนินงานแสดงดังตารางที่ 1.2", "แผนการดำเนินงานแสดงดังตารางที่ 1.2 " + ACTUAL)

# ---------- B6: 2.2.3 ----------
fix("ติดตามเหตุการณ์ทั้ง 5 ประเภทที่โครงงานนี้ใช้", "ติดตามเหตุการณ์ทั้ง 5 ประเภทที่ระบบรุ่นที่ 1 ใช้")
fix("เพื่อควบคุมปริมาณข้อมูลและภาระต่อระบบ",
    "เพื่อควบคุมปริมาณข้อมูลและภาระต่อระบบ ส่วนระบบรุ่นที่ 2 เก็บเหตุการณ์ระดับผลกระทบเพิ่มตามหัวข้อ 3.6")

# ---------- B7: 5.1 ข้อ 4, 5.2 ----------
fix("เพราะระบบไม่ได้เก็บเหตุการณ์การเขียนไฟล์ ภายใต้ชุดทดสอบนี้",
    "เพราะระบบรุ่นที่ 1 ไม่ได้เก็บเหตุการณ์การเขียนไฟล์ ซึ่งรุ่นที่ 2 มองเห็นแล้วผ่านเหตุการณ์ close และ truncate "
    "ภายใต้ชุดทดสอบนี้")
fix("ตรวจโครงสร้างของเหตุการณ์ทั้ง 5 ประเภทกับข้อมูลจริง",
    "ตรวจโครงสร้างของเหตุการณ์ทั้ง 5 ประเภทของรุ่นที่ 1 และเหตุการณ์ที่เพิ่มในรุ่นที่ 2 กับข้อมูลจริง")

# ---------- B8: 4.3 ----------
fix("กำกับเทคนิค T1059.006 13 test ที่มีเพียง", "กำกับเทคนิค T1059.006 นอกจากนี้มี 13 test ที่มีเพียง")

# ---------- B9: หมายเหตุใต้ตารางที่ 4.15 ----------
m = E.para("แถวแยกชนิดนับรวม variant ชุด dev และ eval")
t = html.unescape(T.ptext(m))
first, rest = t.split("  * ", 1)
E.put(m, T.rewrite_para(m, first) + T.rewrite_para(m, "* " + rest))

# ---------- B10: คำย่อ ----------
tbl = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*>ATT&amp;CK<.*?</w:tbl>", E.doc, re.S)
rows = re.findall(r"<w:tr[ >].*?</w:tr>", tbl.group(0), re.S)
hdr, data = rows[0], rows[1:]
tpl = data[0]


def cells(r):
    return [html.unescape("".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", c))) for c in re.findall(r"<w:tc>.*?</w:tc>", r, re.S)]


def mkrow(a, b):
    cs = re.findall(r"<w:tc>.*?</w:tc>", tpl, re.S)
    fill = [re.sub(r"<w:t[^>]*>[^<]*</w:t>", f'<w:t xml:space="preserve">{escape(v)}</w:t>', c) for c, v in zip(cs, (a, b))]
    return tpl[:tpl.index("<w:tc>")] + "".join(fill) + "</w:tr>"


entries = {cells(r)[0]: cells(r)[1] for r in data}
entries.update({"ISO": "International Organization for Standardization",
                "TCP": "Transmission Control Protocol", "UDP": "User Datagram Protocol"})
E.doc = (E.doc[:tbl.start()] + tbl.group(0)[:tbl.group(0).index(hdr)] + hdr
         + "".join(mkrow(k, entries[k]) for k in sorted(entries, key=str.upper)) + "</w:tbl>" + E.doc[tbl.end():])

# ---------- B11: รูปที่ 2.5 ----------
cap = E.doc.index(">รูปที่ 2.5 ")
s = E.doc.rfind("<w:drawing", 0, cap)
e = E.doc.index("</w:drawing>", s)
seg = E.doc[s:e]
rid = re.search(r'r:embed="(rId\d+)"', seg).group(1)
target = re.search(rf'Id="{rid}"[^>]*Target="([^"]+)"', T.rels).group(1)
assert target == "media/image10.png" and E.doc.count(f'r:embed="{rid}"') == 1
shutil.copy(os.path.join(FIGS, "fig25_eslogger_cropped.png"), os.path.join(T.U, "word", target))
cx = int(5.6 * 914400)
cy = int(cx * 176 / 962)
seg2 = re.sub(r'<wp:extent cx="\d+" cy="\d+"/>', f'<wp:extent cx="{cx}" cy="{cy}"/>', seg)
seg2 = re.sub(r'<a:ext cx="\d+" cy="\d+"/>', f'<a:ext cx="{cx}" cy="{cy}"/>', seg2)
E.doc = E.doc[:s] + seg2 + E.doc[e:]

T.write_doc(E.doc)
T.save_rels()
