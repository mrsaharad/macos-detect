"""สร้างสารบัญ สารบัญตาราง และสารบัญรูป ตามรูปแบบคู่มือ (ตัวอย่างที่ 8–10)
- รายการ: บทที่ N + หัวข้อ x.x (Heading2), บรรณานุกรม, ภาคผนวก, ประวัติผู้เขียน, คำบรรยายตาราง/รูป (ย่อหน้าตัวหนา)
- เลขหน้า: แปลงเป็น PDF ด้วย LibreOffice แล้วอ่านเลขหน้าที่พิมพ์บนหัวกระดาษ วนซ้ำจนเลขหน้าคงที่
- หน้าที่รายการล้นไปหน้าถัดไป ใส่หัว "สารบัญ (ต่อ)" + "หน้า" ตามคู่มือ
ข้อจำกัด: เลขหน้าคิดจากการจัดหน้าของ LibreOffice ถ้า Word ตัดหน้าต่างไปเล็กน้อย ต้องตรวจในเล่มอีกครั้ง
วิธีใช้: python build_toc.py <docx ต้นฉบับ> <โฟลเดอร์ทำงาน>   → <โฟลเดอร์ทำงาน>/out.docx, out.pdf"""
import os
import re
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402
from thesislib import escape  # noqa: E402

SRC, W = sys.argv[1], sys.argv[2]
SOFFICE = "/Applications/LibreOffice.app/Contents/MacOS/soffice"
TAB_POS = 8300          # ความกว้างข้อความของหน้าส่วนต้น (11900 - 2160 - 1440)
PAT = r"<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>"


def text(x):
    return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", x)).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")


def norm(s):
    return re.sub(r"\s+", "", s)


# ---------------- รายการจากเนื้อหา ----------------
def collect(doc):
    ms = list(re.finditer(PAT, doc, re.S))
    body = next(i for i, m in enumerate(ms) if text(m.group(0)).strip() == "บทที่ 1")
    toc, tbls, figs = [], [], []
    for i in range(body, len(ms)):
        g = ms[i].group(0)
        if g.startswith("<w:tbl>") or "<w:drawing" in g:     # ย่อหน้าที่มีรูปภาพมีข้อความคำบรรยายซ้ำอยู่ในตัว
            continue
        t = text(g).strip()
        nxt = text(ms[i + 1].group(0)).strip() if i + 1 < len(ms) else ""
        if re.fullmatch(r"บทที่ \d+", t):
            toc.append(("chapter", f"{t}  {nxt}", t + nxt))
        elif 'w:val="Heading2"' in g and re.match(r"\d+\.\d+ ", t):
            toc.append(("section", t, t))
        elif t in ("บรรณานุกรม", "ประวัติผู้เขียน") and len(t) < 20:
            toc.append(("chapter", t, t))
        elif re.fullmatch(r"ภาคผนวก [ก-ฮ]", t):
            toc.append(("chapter", f"{t}  {nxt}", t + nxt))
        elif "<w:b/>" in g and re.match(r"ตาราง(ภาคผนวก)?ที่ [ก-ฮ0-9]+\.\d+ ", t):
            tbls.append(t)
        elif "<w:b/>" in g and re.match(r"รูป(ภาคผนวก)?ที่ [ก-ฮ0-9]+\.\d+ ", t):
            figs.append(t)
    return toc, tbls, figs


FRONT = ["บทคัดย่อ", "Abstract", "กิตติกรรมประกาศ", "สารบัญ", "สารบัญตาราง", "สารบัญรูป", "สัญลักษณ์และคำย่อ"]


# ---------------- XML ----------------
def ppr(left, hanging, before=0, keep=False, tabs=""):
    return (f'<w:pPr>{"<w:keepNext/>" if keep else ""}<w:tabs>{tabs}'
            f'<w:tab w:val="right" w:leader="dot" w:pos="{TAB_POS}"/></w:tabs>'
            f'<w:spacing w:before="{before}" w:after="0" w:line="240" w:lineRule="auto"/>'
            f'<w:ind w:left="{left}" w:right="400" w:hanging="{hanging}"/>{T.RPR}</w:pPr>')


def entry(label, page, left=0, hanging=0, before=0, num=None):
    tabs = f'<w:tab w:val="left" w:pos="{left}"/>' if num else ""
    head = (T.run(num) + '<w:r><w:tab/></w:r>') if num else ""
    return (f'<w:p>{ppr(left, hanging, before, tabs=tabs)}{head}{T.run(label)}'
            f'<w:r><w:tab/></w:r>{T.run(str(page))}</w:p>')


def plain(t, jc="left", before=0, page_break=False):
    return (f'<w:p><w:pPr>{"<w:pageBreakBefore/>" if page_break else ""}'
            f'<w:spacing w:before="{before}" w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="{jc}"/>'
            f'{T.RPR}</w:pPr>{T.run(t)}</w:p>')


def cont_header(title_tpl, title, sub=None):
    """หัวหน้าต่อ: ใช้ย่อหน้าชื่อเดิมเป็นแม่แบบ (มี pageBreakBefore อยู่แล้ว) + 'หน้า' + ป้ายคอลัมน์"""
    t = re.sub(r"<w:t[^>]*>[^<]*</w:t>", f'<w:t xml:space="preserve">{escape(title)}</w:t>', title_tpl, count=1)
    return t + plain("หน้า", "right") + (plain(sub) if sub else "")


def build(doc, pages, breaks):
    toc, tbls, figs = collect(doc)
    ms = list(re.finditer(PAT, doc, re.S))
    idx = {text(m.group(0)).strip(): i for i, m in enumerate(ms[:200]) if text(m.group(0)).strip() in
           ("สารบัญ", "สารบัญตาราง", "สารบัญรูป", "สัญลักษณ์และคำย่อ")}
    tpl = {k: ms[idx[k]].group(0) for k in ("สารบัญ", "สารบัญตาราง", "สารบัญรูป")}

    # --- สารบัญ ---
    out = []
    for k in FRONT:
        out.append(("f:" + k, entry(k, pages.get("f:" + k, "?"))))
    for n, (kind, label, _) in enumerate(toc):
        key = f"t:{n}"
        if kind == "chapter":
            out.append((key, entry(label, pages.get(key, "?"), before=120)))
        else:
            out.append((key, entry(label, pages.get(key, "?"), left=600)))
    toc_xml = "".join((cont_header(tpl["สารบัญ"], "สารบัญ (ต่อ)") if k in breaks else "") + x for k, x in out)

    def listing(items, prefix, word, title, appx_word):
        res, appx = [], False
        for n, cap in enumerate(items):
            m = re.match(rf"{prefix}(ภาคผนวก)?ที่ ([ก-ฮ0-9]+\.\d+) (.*)", cap)
            key = f"{prefix}:{n}"
            if m.group(1) and not appx:
                appx = True
                res.append((key + "h", plain(appx_word, before=120)))
            h = cont_header(tpl[title], f"{title} (ต่อ)", appx_word if appx else word) if key in breaks else ""
            res.append((key, h + entry(m.group(3), pages.get(key, "?"), left=720, hanging=720, num=m.group(2))))
        return plain(word) + "".join(x for _, x in res)

    tbl_xml = listing(tbls, "ตาราง", "ตารางที่", "สารบัญตาราง", "ตารางภาคผนวกที่")
    fig_xml = listing(figs, "รูป", "รูปที่", "สารบัญรูป", "รูปภาคผนวกที่")

    # แทนย่อหน้าหลัง 'หน้า' ของแต่ละรายการ (ร่างสีเทาเดิม หรือรายการที่สร้างรอบก่อน) จนถึงหัวรายการถัดไป
    def replace_between(title, next_title, xml):
        nonlocal doc
        ms2 = list(re.finditer(PAT, doc, re.S))
        a = next(i for i, m in enumerate(ms2) if text(m.group(0)).strip() == title)
        b = next(i for i, m in enumerate(ms2) if i > a and text(m.group(0)).strip() == next_title)
        assert text(ms2[a + 1].group(0)).strip() == "หน้า"
        doc = doc[:ms2[a + 1].end()] + xml + doc[ms2[b].start():]

    replace_between("สารบัญ", "สารบัญตาราง", toc_xml)
    replace_between("สารบัญตาราง", "สารบัญรูป", tbl_xml)
    replace_between("สารบัญรูป", "สัญลักษณ์และคำย่อ", fig_xml)
    return doc, toc, tbls, figs


# ---------------- อ่านเลขหน้าจาก PDF ----------------
def pdf_pages(pdf):
    raw = subprocess.run(["pdftotext", pdf, "-"], capture_output=True, text=True, check=True).stdout.split("\f")
    labels, texts = [], []
    for p in raw:
        lines = [ln for ln in p.split("\n") if ln.strip()]
        first = lines[0].strip() if lines else ""
        lab = first if re.fullmatch(r"\d+|[ก-ฮ]{1,2}", first) else None
        labels.append(lab)
        texts.append(norm("\n".join(lines[1:] if lab else lines)))
    # หน้าแรกของบทไม่มีเลขหน้า → ใช้เลขของหน้าถัดไป - 1
    for i in range(len(labels) - 2, -1, -1):
        if labels[i] is None and labels[i + 1] and labels[i + 1].isdigit():
            labels[i] = str(int(labels[i + 1]) - 1)
    for i in range(1, len(labels)):              # หน้าสุดท้ายที่ไม่มีเลข (เช่น ประวัติผู้เขียน)
        if labels[i] is None and labels[i - 1] and labels[i - 1].isdigit():
            labels[i] = str(int(labels[i - 1]) + 1)
    return labels, texts


def locate(toc, tbls, figs, labels, texts):
    pages = {}
    body = next(i for i, t in enumerate(texts) if t.startswith("บทที่1") and "สารบัญ" not in t)
    pos = 0
    for k in FRONT:
        h = norm(k)
        if k in ("บทคัดย่อ", "Abstract"):
            hit = next(i for i in range(pos, body) if h in texts[i])
        else:
            hit = next(i for i in range(pos, body) if texts[i].startswith(h) and not texts[i].startswith(h + "ตาราง")
                       and not texts[i].startswith(h + "รูป"))
        pages["f:" + k], pos = labels[hit], hit
    for name, items, conv in (("t", toc, lambda e: e[2]), ("ตาราง", tbls, None), ("รูป", figs, None)):
        pos = body
        for n, it in enumerate(items):
            needle = norm(conv(it) if conv else it)[:40]
            hit = next((i for i in range(pos, len(texts)) if needle in texts[i]), None)
            assert hit is not None, f"ไม่พบ {needle}"
            pages[f"{name}:{n}"], pos = labels[hit], hit
    return pages


def overflow_breaks(toc, tbls, figs, texts):
    """หาว่ารายการไหนเป็นรายการแรกของหน้าถัดไปในแต่ละรายการสารบัญ (ไม่นับหน้าที่มีหัว (ต่อ) อยู่แล้ว)"""
    br = set()
    groups = (("สารบัญ", [("f:" + k, norm(k)) for k in FRONT] + [(f"t:{n}", norm(e[1])[:25]) for n, e in enumerate(toc)]),
              ("สารบัญตาราง", [(f"ตาราง:{n}", norm(re.sub(r"^ตาราง(ภาคผนวก)?ที่ [ก-ฮ0-9]+\.\d+ ", "", t))[:25]) for n, t in enumerate(tbls)]),
              ("สารบัญรูป", [(f"รูป:{n}", norm(re.sub(r"^รูป(ภาคผนวก)?ที่ [ก-ฮ0-9]+\.\d+ ", "", t))[:25]) for n, t in enumerate(figs)]))
    for title, items in groups:
        start = next(i for i, t in enumerate(texts) if t.startswith(norm(title) + "หน้า"))
        for p in range(start + 1, len(texts)):
            t = texts[p]
            if t.startswith(norm(title) + "(ต่อ)"):
                continue
            if not any(t.startswith(norm(x)) for x in ("สารบัญตาราง", "สารบัญรูป", "สัญลักษณ์")) and items:
                # หน้าต่อแบบไม่มีหัว: รายการแรกที่ปรากฏบนหน้านี้
                first = min(((t.find(nd), k) for k, nd in items if t.find(nd) >= 0), default=None)
                if first:
                    br.add(first[1])
                    continue
            break
    return br


def render(doc, tag):
    d = os.path.join(W, "u")
    open(os.path.join(d, "word/document.xml"), "w", encoding="utf-8").write(doc)
    out = os.path.join(W, "out.docx")
    if os.path.exists(out):
        os.remove(out)
    subprocess.run(f'cd "{d}" && zip -XrDyq ../out.docx .', shell=True, check=True)
    subprocess.run([SOFFICE, "--headless", "--convert-to", "pdf", "--outdir", W, out], capture_output=True, check=True)
    return pdf_pages(os.path.join(W, "out.pdf"))


shutil.rmtree(os.path.join(W, "u"), ignore_errors=True)
os.makedirs(W, exist_ok=True)
zipfile.ZipFile(SRC).extractall(os.path.join(W, "u"))
T.open_doc(os.path.join(W, "u"))
orig = T.read_doc()

pages, breaks = {}, set()
for it in range(6):
    doc, toc, tbls, figs = build(orig, pages, breaks)
    labels, texts = render(doc, it)
    new_pages = locate(toc, tbls, figs, labels, texts)
    new_breaks = breaks | overflow_breaks(toc, tbls, figs, texts)
    print(f"รอบ {it + 1}: รายการสารบัญ {len(toc)}, ตาราง {len(tbls)}, รูป {len(figs)}, "
          f"เปลี่ยนเลขหน้า {sum(new_pages.get(k) != pages.get(k) for k in new_pages)}, หัว (ต่อ) {sorted(new_breaks)}",
          file=sys.stderr)
    if new_pages == pages and new_breaks == breaks:
        break
    pages, breaks = new_pages, new_breaks
else:
    sys.exit("เลขหน้าไม่นิ่งหลัง 6 รอบ")
