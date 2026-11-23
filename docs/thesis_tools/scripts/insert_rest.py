"""Add front matter (approval page .. abbreviations), chapter 5, bibliography, appendices and author bio.
Usage: python3 insert_rest.py <unpacked_dir>   (run after insert3x.py)
"""
import re
import sys
from xml.sax.saxutils import escape

import yaml

# reuse the helpers (run, intro, body, h2, h3, draft, table, listing, captions...) from insert3x.py
src = open("/home/claude/thesis/insert3x.py", encoding="utf-8").read()
exec(src[:src.index("# ================================================================ 3.3")])

GREY_INLINE = RPR_GREY
TITLE_RPR = f'<w:rPr>{FONT}<w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="36"/><w:szCs w:val="36"/><w:cs/></w:rPr>'


def P(parts, jc="left", before=0, after=0, ind="", page_break=False, rpr=RPR):
    """paragraph from [(text, grey?)] parts"""
    runs = "".join(run(t, GREY_INLINE if g else rpr) for t, g in parts)
    pb = "<w:pageBreakBefore/>" if page_break else ""
    return (f'<w:p><w:pPr>{pb}<w:spacing w:before="{before}" w:after="{after}"/>{ind}<w:jc w:val="{jc}"/>{rpr}</w:pPr>'
            f'{runs}</w:p>')


def center(text, bold=False, after=0, before=0, page_break=False, grey=False):
    rpr = RPR_B if bold else RPR
    return P([(text, grey)], "center", before, after, page_break=page_break, rpr=rpr)


def title(text, page_break=True):
    """front/back matter page title: 18 pt bold centred, like the chapter titles"""
    pb = "<w:pageBreakBefore/>" if page_break else ""
    return (f'<w:p><w:pPr>{pb}<w:spacing w:before="0" w:after="360" w:line="240" w:lineRule="auto"/>'
            f'<w:jc w:val="center"/>{TITLE_RPR}</w:pPr>{run(text, TITLE_RPR)}</w:p>')


def chapter(no, name):
    return (f'<w:p><w:pPr><w:spacing w:before="720" w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>'
            f'{run(no, TITLE_RPR)}</w:p>'
            f'<w:p><w:pPr><w:spacing w:after="360" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>'
            f'{run(name, TITLE_RPR)}</w:p>')


def sect_end(extra="", pgnum=""):
    """paragraph that ends a section (next part starts on a new page, first page without number)"""
    return (f'<w:p><w:pPr><w:spacing w:after="0"/>{RPR}<w:sectPr>{extra}<w:pgSz w:w="11900" w:h="16840"/>'
            '<w:pgMar w:top="2160" w:right="1440" w:bottom="1440" w:left="2160" w:header="1417" w:footer="680" w:gutter="0"/>'
            f'{pgnum}<w:cols w:space="708"/><w:titlePg/><w:docGrid w:linePitch="360"/></w:sectPr></w:pPr></w:p>')


def plain_table(rows, widths):
    """borderless table for label : value lines (abstract header, bio)"""
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    out = (f'<w:tbl><w:tblPr><w:tblW w:w="{sum(widths)}" w:type="dxa"/><w:tblBorders><w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/>'
           '<w:insideH w:val="nil"/><w:insideV w:val="nil"/></w:tblBorders><w:tblLayout w:type="fixed"/>'
           '<w:tblCellMar><w:left w:w="0" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr>'
           f'<w:tblGrid>{grid}</w:tblGrid>')
    for r in rows:
        out += "<w:tr>"
        for cellv, w in zip(r, widths):
            parts = cellv if isinstance(cellv, list) else [(cellv, False)]
            runs = "".join(run(t, GREY_INLINE if g else RPR) for t, g in parts)
            out += (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/></w:tcPr>'
                    f'<w:p><w:pPr><w:spacing w:after="0"/>{RPR}</w:pPr>{runs}</w:p></w:tc>')
        out += "</w:tr>"
    return out + "</w:tbl>"


def dots_line(role):
    return P([("..................................................................  ", False), (role, False)], "right", before=360)


RPR_I = RPR.replace("<w:color", "<w:i/><w:iCs/><w:color")


def bib(parts):
    """APA entry: hanging indent 0.5 in, single spacing"""
    runs = "".join(run(t, GREY_INLINE if g == 1 else RPR_I if g == "i" else RPR) for t, g in parts)
    return (f'<w:p><w:pPr><w:spacing w:after="120" w:line="240" w:lineRule="auto"/><w:ind w:left="720" w:hanging="720"/>'
            f'<w:jc w:val="left"/>{RPR}</w:pPr>{runs}</w:p>')


TH_TITLE = "ระบบตรวจจับภัยคุกคามบน macOS ด้วยข้อมูลระดับระบบปฏิบัติการ"
EN_TITLE = "macOS Threat Detection Using OS-Level Telemetry"

# ================================================================ ใบรับรองปริญญานิพนธ์ (ต่อจากปกนอก ก่อนปกใน)
APPROVAL = [
    center("ปริญญานิพนธ์เรื่อง", bold=True, page_break=True),
    center(TH_TITLE, bold=True),
    center("(MACOS THREAT DETECTION USING OS-LEVEL TELEMETRY)", bold=True, after=240),
    center("โดย", bold=True),
    center("นายสหรัตน์ ทรัพย์แสง  6601190", bold=True, after=240),
    center("ได้รับการพิจารณาให้เป็นส่วนหนึ่งของการศึกษาตามหลักสูตร"),
    center("วิศวกรรมศาสตรบัณฑิต สาขาวิชาวิศวกรรมคอมพิวเตอร์"),
    center("วิทยาลัยวิศวกรรมศาสตร์ มหาวิทยาลัยรังสิต"),
    center("ปีการศึกษา 2569", after=120),
    dots_line("ประธานกรรมการสอบ"),
    P([("(", False), ("ตำแหน่งวิชาการ ชื่อ นามสกุล ของประธานกรรมการ", True), (")", False)], "right", ind='<w:ind w:right="1900"/>'),
    dots_line("กรรมการ"),
    P([("(", False), ("ตำแหน่งวิชาการ ชื่อ นามสกุล ของกรรมการ", True), (")", False)], "right", ind='<w:ind w:right="1900"/>'),
    dots_line("กรรมการและอาจารย์ที่ปรึกษา"),
    P([("(", False), ("ตำแหน่งวิชาการ ชื่อ นามสกุล ของอาจารย์ที่ปรึกษา", True), (")", False)], "right", ind='<w:ind w:right="1900"/>'),
    center("..................................................................", before=480),
    P([("(ดร. ชนินท์ วงษ์ใหญ่)  ", False), ("ตรวจชื่อหัวหน้าหลักสูตรปัจจุบันกับภาควิชา", True)], "center"),
    center("หัวหน้าหลักสูตรวิศวกรรมศาสตรบัณฑิต"),
    center("สาขาวิชาวิศวกรรมคอมพิวเตอร์"),
    center("วันที่ .......... เดือน ............................... พ.ศ. ..............", before=120),
    '<w:p><w:r><w:br w:type="page"/></w:r></w:p>',
]

# ================================================================ ส่วนหน้า (หน้า ข เป็นต้นไป)
FRONT = []
# บทคัดย่อ
FRONT.append(plain_table([
    ["ชื่อ", ": นายสหรัตน์ ทรัพย์แสง", "รหัส 6601190"],
    ["เรื่อง", ": " + TH_TITLE, ""],
    ["อาจารย์ที่ปรึกษา", [(": ", False), ("ตำแหน่ง ชื่อ นามสกุล อาจารย์ที่ปรึกษา", True), (", จำนวนหน้าทั้งหมด ", False),
                          ("...", True), (" หน้า", False)], ""],
    ["คำสำคัญ", ": macOS, Endpoint Security Framework, การตรวจจับเชิงพฤติกรรม, Sigma, MITRE ATT&CK", ""],
], [1900, 5000, 1400]))
FRONT.append(title("บทคัดย่อ", page_break=False).replace('w:before="0"', 'w:before="360"'))
FRONT.append(intro(
    "ระบบป้องกันที่มาพร้อม macOS เช่น Gatekeeper และ XProtect ตัดสินจากคุณสมบัติของตัวไฟล์เป็นหลัก จึงตรวจจับการโจมตีแบบ "
    "Living off the Land ซึ่งใช้โปรแกรมของระบบที่มีลายเซ็นของ Apple ได้ยาก โครงงานนี้จึงพัฒนาระบบตรวจจับภัยคุกคามเชิงพฤติกรรม"
    "บน macOS ที่ใช้ข้อมูลระดับระบบปฏิบัติการจาก Endpoint Security Framework ผ่านเครื่องมือ eslogger ที่มากับระบบ ระบบทำหน้าที่"
    "ตรวจจับและแจ้งเตือนเท่านั้น และเปิดเผยกฎตรวจจับทั้งหมดให้ตรวจสอบได้"))
FRONT.append(intro(
    "ระบบประกอบด้วยส่วนเก็บข้อมูลซึ่งรับเหตุการณ์ 5 ประเภท ได้แก่ exec, fork, create, rename และ unlink ส่วนแปลงข้อมูลให้อยู่ใน"
    "รูปแบบกลางตามแนวทางของ Sigma ส่วนตรวจจับซึ่งเปรียบเทียบเหตุการณ์กับกฎรูปแบบ YAML จำนวน 25 กฎ ครอบคลุม 6 ยุทธวิธีของ "
    "MITRE ATT&CK ฐานข้อมูล SQLite และ Dashboard ที่พัฒนาด้วย Streamlit การประเมินผลใช้ชุดทดสอบ Atomic Red Team ซึ่งแบ่งเป็น"
    "ชุดสำหรับปรับปรุงกฎและชุดสำหรับวัดผล โดยวัดอัตราการตรวจจับ อัตราการแจ้งเตือนเท็จ ระยะเวลาในการตรวจจับ และภาระต่อทรัพยากร"
    "เครื่อง พร้อมวิเคราะห์ช่องว่างของการมองเห็น (Visibility Gap)"))
FRONT.append(draft("ย่อหน้าที่ 3 (จากบทที่ 5): ผลการทดสอบสำคัญ เช่น Detection Rate ของชุด eval, จำนวนการแจ้งเตือนเท็จต่อชั่วโมง, "
                   "ค่ากลางของ latency, เทคนิคที่มองไม่เห็น และแนวทางพัฒนาต่อ ทั้งบทคัดย่อรวมไม่เกิน 300 คำ"))
# Abstract
FRONT.append(plain_table([
    ["Name", [(": ", False), ("ชื่อ นามสกุล ภาษาอังกฤษ (ไม่ต้องมี Mr.)", True)], "ID 6601190"],
    ["Title", ": " + EN_TITLE, ""],
    ["Advisor", [(": ", False), ("ตำแหน่ง ชื่อ นามสกุล อาจารย์ที่ปรึกษา (ภาษาอังกฤษ)", True), (", ", False), ("...", True), (" pages.", False)], ""],
    ["Keywords", ": macOS, Endpoint Security Framework, Behavioral Detection, Sigma, MITRE ATT&CK", ""],
], [1900, 5000, 1400]).replace("<w:tbl>", "<w:p><w:pPr><w:pageBreakBefore/><w:spacing w:after=\"0\"/></w:pPr></w:p><w:tbl>", 1))
FRONT.append(title("Abstract", page_break=False).replace('w:before="0"', 'w:before="360"'))
FRONT.append(intro(
    "Built-in macOS defenses such as Gatekeeper and XProtect mainly judge files by their properties. They are therefore weak "
    "against living-off-the-land attacks, which use system programs that already carry Apple's signature. This project develops "
    "a behavioral threat detection system for macOS. It uses operating-system telemetry from the Endpoint Security Framework, "
    "collected with the built-in eslogger tool. The system only detects and alerts, and all of its detection rules are open "
    "for review."))
FRONT.append(intro(
    "The system has a collector for five event types (exec, fork, create, rename and unlink), a normalizer that maps raw events "
    "to Sigma-style fields, a rule engine that matches events against 25 YAML rules covering six MITRE ATT&CK tactics, a SQLite "
    "store and a Streamlit dashboard. It is evaluated with Atomic Red Team tests, split into a development set for tuning the "
    "rules and an evaluation set for measurement. The evaluation reports detection rate, false positive rate, detection latency "
    "and system overhead, and analyzes the visibility gap of the telemetry."))
FRONT.append(draft("Paragraph 3 (from chapter 5): key results and future work, matching the Thai abstract. Keep the whole abstract under 300 words."))
# กิตติกรรมประกาศ
FRONT.append(title("กิตติกรรมประกาศ"))
FRONT.append(P([("ปริญญานิพนธ์ฉบับนี้สำเร็จลุล่วงได้ด้วยความกรุณาของ ", False), ("ตำแหน่ง ชื่อ นามสกุล", True),
                (" อาจารย์ที่ปรึกษา ซึ่งให้คำแนะนำและตรวจทานงานตลอดการดำเนินโครงงาน และขอขอบพระคุณ ", False),
                ("ชื่อกรรมการสอบ", True), (" ที่ให้ข้อเสนอแนะอันเป็นประโยชน์ต่อการปรับปรุงงาน", False)],
               "both", after=120, ind='<w:ind w:firstLine="720"/>'))
FRONT.append(draft("ขอบคุณบุคคลอื่นตามที่ต้องการ เช่น ครอบครัว เพื่อน และหน่วยงานที่ฝึกงาน ความยาวรวมไม่เกิน 1 หน้า"))
FRONT.append(center("นายสหรัตน์ ทรัพย์แสง", before=720).replace('w:jc w:val="center"', 'w:jc w:val="right"'))
FRONT.append(P([("ผู้เขียน", False)], "right", ind='<w:ind w:right="700"/>'))
# สารบัญ
for t, note in [
    ("สารบัญ", "สร้างเมื่อเนื้อหาครบแล้ว ตามรูปแบบในคู่มือ: บทคัดย่อ, Abstract, กิตติกรรมประกาศ, สารบัญ, สารบัญตาราง, สารบัญรูป, "
               "สัญลักษณ์และคำย่อ แล้วตามด้วยบทที่ 1–5 พร้อมหัวข้อระดับ x.x (ไม่ใส่หัวข้อ x.x.x), บรรณานุกรม, ภาคผนวก ก–ง "
               "และประวัติผู้เขียน เลขหน้าชิดขวา"),
    ("สารบัญตาราง", "รายการตารางทุกตารางในบทที่ 1–4 และตารางภาคผนวกที่ ข.1, ค.1, ง.1 พร้อมเลขหน้า"),
    ("สารบัญรูป", "รายการรูปทุกรูปในบทที่ 1–4 พร้อมเลขหน้า"),
]:
    FRONT.append(title(t))
    FRONT.append(P([("หน้า", False)], "right"))
    FRONT.append(draft(note))
# สัญลักษณ์และคำย่อ
FRONT.append(title("สัญลักษณ์และคำย่อ"))
FRONT.append(table(["คำย่อ", "ความหมาย"], [
    ["ATT&CK", "Adversarial Tactics, Techniques, and Common Knowledge"],
    ["DFD", "Data Flow Diagram (แผนภาพกระแสข้อมูล)"],
    ["EDR", "Endpoint Detection and Response"],
    ["ER", "Entity-Relationship"],
    ["ESF", "Endpoint Security Framework"],
    ["FN", "False Negative"],
    ["FP", "False Positive"],
    ["FPR", "False Positive Rate (อัตราการแจ้งเตือนเท็จ)"],
    ["JSON", "JavaScript Object Notation"],
    ["PID / PPID", "Process ID / Parent Process ID (หมายเลขโปรเซส / หมายเลขโปรเซสแม่)"],
    ["SOC", "Security Operations Center (ศูนย์ปฏิบัติการด้านความมั่นคงปลอดภัย)"],
    ["SQL", "Structured Query Language"],
    ["TN", "True Negative"],
    ["TP", "True Positive"],
    ["UTC", "Coordinated Universal Time"],
    ["WAL", "Write-Ahead Logging"],
    ["YAML", "YAML Ain't Markup Language (รูปแบบไฟล์ข้อความสำหรับเก็บข้อมูลเชิงโครงสร้าง)"],
], [2300, 6000]))
FRONT.append(draft("ตัดคำที่ไม่ได้ใช้ในเล่มออก และเพิ่มคำย่ออื่นที่ใช้ในบทที่ 1–2"))
FRONT.append(sect_end("", '<w:pgNumType w:fmt="thaiLetters" w:start="2"/>').replace("<w:titlePg/>", ""))

# ================================================================ บทที่ 5
CH5 = [sect_end(), chapter("บทที่ 5", "สรุปผลและข้อเสนอแนะ")]
CH5.append(intro(
    "บทนี้สรุปผลการดำเนินโครงงานเทียบกับวัตถุประสงค์ในหัวข้อ 1.2 ปัญหาและอุปสรรคที่พบระหว่างการพัฒนาและการทดสอบ และแนวทาง"
    "การพัฒนาระบบต่อในอนาคต"))
CH5.append(h2("5.1 สรุปผลการดำเนินงาน"))
CH5.append(intro(
    "โครงงานนี้พัฒนาระบบตรวจจับภัยคุกคามเชิงพฤติกรรมบน macOS ที่ทำงานได้จริงบนเครื่องเดียว ตั้งแต่การรับเหตุการณ์จาก eslogger "
    "การแปลงข้อมูล การตรวจจับตามกฎ การจัดเก็บ จนถึงการแสดงผลบน Dashboard ผลการดำเนินงานเทียบกับวัตถุประสงค์แต่ละข้อมีดังนี้"))
CH5.append(body(
    "วัตถุประสงค์ข้อที่ 1 ระบบเก็บและจัดเตรียมข้อมูลเหตุการณ์ exec, fork, create, rename และ unlink จาก Endpoint Security Framework "
    "แบบเรียลไทม์ได้ และแปลงข้อมูลให้อยู่ในรูปแบบกลางที่ตรวจสอบแล้วว่าถูกต้องกับข้อมูลจริงบน macOS 27.2"))
CH5.append(body(
    "วัตถุประสงค์ข้อที่ 2 ระบบมีกฎตรวจจับรูปแบบ YAML ตามแนวคิด Sigma จำนวน 25 กฎ ครอบคลุม 6 ยุทธวิธีของ MITRE ATT&CK "
    "ซึ่งมากกว่าเป้าหมายขั้นต่ำ 20 กฎและ 5 ยุทธวิธี"))
CH5.append(draft("วัตถุประสงค์ข้อที่ 3: สรุปตัวเลขจากบทที่ 4 ได้แก่ Detection Rate ของชุด eval, FPR และจำนวน FP ต่อชั่วโมง, Precision, "
                 "latency (ค่ากลาง/P95/สูงสุด) และการใช้ CPU/RAM"))
CH5.append(draft("วัตถุประสงค์ข้อที่ 4: สรุปจำนวนเทคนิคในแต่ละกลุ่ม Detected / Visible-Not Detected / Not Visible และสาเหตุหลักของ Visibility Gap"))

CH5.append(h2("5.2 ปัญหาและอุปสรรค"))
CH5.append(intro(
    "ระหว่างการพัฒนาและทดสอบระบบ พบปัญหาและอุปสรรคที่สำคัญดังต่อไปนี้ พร้อมวิธีที่ใช้แก้ไขหรือรับมือ"))
for t in [
    "eslogger ต้องรันด้วยสิทธิ์ผู้ดูแลระบบ และ Terminal ต้องได้รับสิทธิ์ Full Disk Access ระบบจึงไม่สามารถทำเป็นแอปที่เปิดได้ด้วยการคลิก"
    "เพียงครั้งเดียว เพราะการเรียกใช้ Endpoint Security โดยตรงต้องได้รับสิทธิ์พิเศษจาก Apple ซึ่งเกินขอบเขตของโครงงาน ผู้จัดทำจึงสร้าง"
    "ไฟล์ start_collector.command ให้ผู้ใช้ดับเบิลคลิกและกรอกรหัสผ่านเพียงครั้งเดียว",
    "eslogger รายงานโปรเซสแม่เป็นเพียงหมายเลขโปรเซส ระบบจึงต้องสร้างตารางจับคู่หมายเลขโปรเซสกับโปรแกรมเอง ทำให้ไม่ทราบโปรแกรมแม่"
    "ของโปรเซสที่เริ่มทำงานก่อนเปิดระบบ ข้อจำกัดนี้บันทึกไว้เป็นส่วนหนึ่งของ Visibility Gap",
    "เมื่อ Dashboard และส่วนตรวจจับเขียนข้อมูลลงไฟล์ฐานข้อมูลเดียวกัน SQLite แจ้งข้อผิดพลาดว่าฐานข้อมูลถูกล็อก ผู้จัดทำแก้ไขโดยให้ส่วน"
    "ตรวจจับบันทึกข้อมูลทันทีทีละรายการ และแยกผลการตัดสินของผู้วิเคราะห์ไปเก็บในไฟล์ verdicts.db ทำให้ Dashboard เปิดฐานข้อมูลหลัก"
    "แบบอ่านอย่างเดียว",
    "ระบบตรวจพบการกระทำของโปรแกรมที่ไม่ใช่การโจมตี เช่น Dashboard รุ่นแรกเรียกคำสั่ง sw_vers เพื่ออ่านเวอร์ชันของระบบ และแอปพลิเคชัน"
    "อื่นบนเครื่องเรียกคำสั่งเดียวกัน ซึ่งตรงกับกฎ MD-0022 ผู้จัดทำแก้ Dashboard ให้อ่านเวอร์ชันจากไฟล์ของระบบแทน และเลือกใช้ afplay "
    "แทน osascript สำหรับเสียงแจ้งเตือน เพื่อไม่ให้ระบบตรวจพบการกระทำของตัวเอง กรณีเหล่านี้แสดงให้เห็นว่ากฎเชิงพฤติกรรมต้องมีขั้นตอน"
    "การตรวจทานโดยผู้วิเคราะห์ และต้องเลือกระดับความรุนแรงให้สอดคล้องกับโอกาสที่จะเป็นการใช้งานปกติ",
    "เอกสารของ eslogger ระบุว่าเครื่องมือนี้ไม่ใช่ API และรูปแบบข้อมูลอาจเปลี่ยนแปลงระหว่างเวอร์ชันของระบบปฏิบัติการ ผู้จัดทำจึง"
    "ตรวจโครงสร้างของเหตุการณ์ทั้ง 5 ประเภทกับข้อมูลจริงที่บันทึกจากเครื่องก่อนเขียนส่วนแปลงข้อมูล "
    "และบันทึกเวอร์ชันพร้อมหมายเลข build ของระบบปฏิบัติการที่ใช้ทดสอบ",
    "ส่วนประกอบสำเร็จรูปของ Streamlit จำกัดการจัดวางและขนาดของปุ่ม ตาราง และช่องกรอกข้อมูล ทำให้หน้าจอไม่เรียบร้อยเท่าที่ออกแบบไว้ "
    "ผู้จัดทำจึงวาดหน้าจอด้วย HTML และ CSS ภายใน component ของ Streamlit แทน",
]:
    CH5.append(body(t))
CH5.append(draft("เพิ่มปัญหาที่พบระหว่างการทดสอบด้วย Atomic Red Team เช่น ชุดทดสอบที่รันไม่สำเร็จเพราะขาดโปรแกรมหรือสิทธิ์"))

CH5.append(h2("5.3 แนวทางการพัฒนาในอนาคต"))
CH5.append(intro("จากผลการดำเนินงานและข้อจำกัดที่พบ ระบบสามารถพัฒนาต่อได้ในแนวทางต่อไปนี้"))
for t in [
    "เพิ่มประเภทเหตุการณ์ที่ใช้ตรวจจับ เช่น การเปิดไฟล์ การเชื่อมต่อเครือข่าย และการแก้ไขสิทธิ์ของไฟล์ เพื่อลด Visibility Gap โดยต้อง"
    "พิจารณาภาระต่อทรัพยากรเครื่องควบคู่กัน",
    "พัฒนากฎที่เชื่อมโยงเหตุการณ์หลายรายการตามลำดับเวลา เช่น การดาวน์โหลดไฟล์แล้วลบป้ายกักกันแล้วรันไฟล์นั้นภายในช่วงเวลาสั้น ๆ "
    "ซึ่งช่วยลดการแจ้งเตือนเท็จของกฎที่พิจารณาเหตุการณ์เดียว",
    "เพิ่มรายการยกเว้นตามลายเซ็นของโปรแกรม (Signing ID) ที่เชื่อถือได้ เพื่อลดการแจ้งเตือนเท็จจากแอปพลิเคชันปกติ",
    "พัฒนาเป็น System Extension ที่ได้รับสิทธิ์ Endpoint Security จาก Apple เพื่อรับเหตุการณ์ได้โดยตรง และรองรับเหตุการณ์ประเภท AUTH "
    "ซึ่งเปิดทางให้ระบบป้องกันหรือบล็อกการกระทำได้ในอนาคต",
    "ส่งการแจ้งเตือนออกไปยังระบบ SIEM ขององค์กร เพื่อรวมข้อมูลจากเครื่อง macOS หลายเครื่องไว้ในศูนย์ปฏิบัติการเดียว",
]:
    CH5.append(body(t))

# ================================================================ บรรณานุกรม
BIB = [sect_end(), title("บรรณานุกรม", page_break=False).replace('w:before="0"', 'w:before="720"')]
BIB.append(draft("เรียงตามคู่มือ: ภาษาไทยก่อนภาษาอังกฤษ ในแต่ละภาษาเรียง วารสาร > หนังสือ > ออนไลน์ และเรียงตามชื่อผู้แต่ง "
                 "รูปแบบ APA 6th Edition บรรทัดที่สองของแต่ละรายการย่อหน้าเข้า ตรวจชื่อเรื่องและ URL ของแหล่งออนไลน์จากที่ใช้จริงในบทที่ 1–2 "
                 "และเพิ่มแหล่งอื่นที่อ้างถึง เช่น Sigma, Atomic Red Team, Streamlit, SQLite"))
BIB.append(bib([("Axelsson, S. (2000). The base-rate fallacy and the difficulty of intrusion detection. ", False),
                ("ACM Transactions on Information and System Security, 3", "i"), ("(3), 186–205.", False)]))
BIB.append(bib([("Sokolova, M., & Lapalme, G. (2009). A systematic analysis of performance measures for classification tasks. ", False),
                ("Information Processing & Management, 45", "i"), ("(4), 427–437.", False)]))
BIB.append(bib([("Apple Inc. (2022). ", False), ("ชื่อเอกสารที่อ้างในบทที่ 2 (เช่น หน้าเอกสาร Endpoint Security หรือ eslogger)", True),
                (". Retrieved from ", False), ("URL", True)]))
BIB.append(bib([("Dediu, ", False), ("อักษรย่อชื่อต้น", True), (" (2026). ", False), ("ชื่อบทความที่อ้างข้อมูล IDC", True), (". Retrieved from ", False), ("URL", True)]))
BIB.append(bib([("MITRE Corporation. (2026). ", False), ("MITRE ATT&CK", "i"), (". Retrieved from https://attack.mitre.org/", False)]))
BIB.append(bib([("Moonlock Lab. (2025). ", False), ("ชื่อรายงาน", True), (". Retrieved from ", False), ("URL", True)]))

# ================================================================ ภาคผนวก
rules = [yaml.safe_load(open(p, encoding="utf-8")) for p in sorted(__import__("glob").glob("/home/claude/md/rules/*.yml"))]
TAC_TH = {"discovery": "สำรวจเครื่อง", "execution": "รันคำสั่ง", "persistence": "ฝังตัวถาวร",
          "credential_access": "ขโมยรหัสผ่าน", "stealth": "ซ่อนร่องรอย", "defense_impairment": "ปิดระบบป้องกัน"}
LV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def appendix(letter, name):
    """title page of an appendix (new section, centred) then a page break"""
    return [sect_end(),
            f'<w:p><w:pPr><w:spacing w:before="4800" w:after="240"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>{run("ภาคผนวก " + letter, TITLE_RPR)}</w:p>',
            f'<w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>{run(name, TITLE_RPR)}</w:p>',
            '<w:p><w:r><w:br w:type="page"/></w:r></w:p>']


APP = []
APP += appendix("ก", "คู่มือการติดตั้งและใช้งานระบบ")
APP.append(h2("1. ความต้องการของระบบ"))
APP.append(intro(
    "เครื่อง Mac ที่ใช้ macOS 13 ขึ้นไป ซึ่งเป็นรุ่นแรกที่มี eslogger ติดตั้ง Python 3.10 ขึ้นไป บัญชีผู้ใช้มีสิทธิ์ผู้ดูแลระบบ และ Terminal "
    "ได้รับสิทธิ์ Full Disk Access ที่ System Settings > Privacy & Security > Full Disk Access"))
APP.append(h2("2. การติดตั้ง"))
APP.append(intro("เปิด Terminal แล้วรันคำสั่งต่อไปนี้ เพื่อดาวน์โหลดโค้ด สร้างสภาพแวดล้อมเสมือนของ Python และติดตั้งไลบรารีที่ใช้"))
APP.append(listing(["git clone https://github.com/mrsaharad/macos-detect.git", "cd macos-detect", "python3 -m venv .venv",
                    "source .venv/bin/activate", "pip install -r requirements.txt", "python tests/test_rules.py"]))
APP.append(after_table())
APP.append(intro("คำสั่งสุดท้ายทดสอบกฎทั้งหมดด้วยเหตุการณ์จำลอง หากติดตั้งถูกต้องจะแสดงผลว่ากฎทั้งหมด 25 ข้อ ผิด 0"))
APP.append(h2("3. การเริ่มใช้งาน"))
APP.append(intro(
    "ดับเบิลคลิกไฟล์ start_collector.command ในโฟลเดอร์โปรเจกต์ แล้วกรอกรหัสผ่านของเครื่อง ระบบจะเริ่มรับเหตุการณ์และตรวจจับ จากนั้น"
    "ดับเบิลคลิกไฟล์ start_dashboard.command เบราว์เซอร์จะเปิด Dashboard ที่ http://localhost:8501 หากต้องการหยุดการทำงาน ให้กด "
    "Control + C ในหน้าต่าง Terminal ของแต่ละส่วน ข้อมูลทั้งหมดเก็บอยู่ในโฟลเดอร์ data"))
APP.append(h2("4. การทดสอบด้วย Atomic Red Team และการคำนวณผล"))
APP.append(intro("ติดตั้ง PowerShell และ Invoke-AtomicRedTeam หนึ่งครั้ง จากนั้นเปิดส่วนตรวจจับไว้ แล้วรันคำสั่งทดสอบและคำนวณผล"))
APP.append(listing(["brew install --cask powershell",
                    "pwsh -c 'IEX (IWR \"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1\" -UseBasicParsing); Install-AtomicRedTeam -getAtomics'",
                    "./attacksim/run_atomic.sh          # รันชุดทดสอบตาม attacksim/plan.txt",
                    "./attacksim/baseline.sh 60         # ใช้เครื่องตามปกติ 60 นาที",
                    "python scripts/report.py           # คำนวณตัวชี้วัด"]))
APP.append(after_table())

APP += appendix("ข", "กฎตรวจจับทั้งหมด")
APP.append(intro(
    "ตารางภาคผนวกที่ ข.1 สรุปกฎตรวจจับทั้ง 25 ข้อ ไฟล์กฎฉบับเต็มอยู่ในโฟลเดอร์ rules ของโปรเจกต์ ตามโครงสร้างในหัวข้อ 3.4.3"))
APP.append(caption_tbl("ตารางภาคผนวกที่ ข.1 กฎตรวจจับทั้งหมด"))
APP.append(table(["รหัสกฎ", "ชื่อกฎ", "ยุทธวิธี", "เทคนิค", "ระดับ"],
                 [[r["id"], r.get("title_th", r["title"]), TAC_TH.get(r["tags"][0].split(".", 1)[1], ""),
                   r["tags"][1].split(".", 1)[1].upper(), LV[r["level"]]] for r in rules],
                 [1350, 3250, 1400, 1300, 1000], center_cols=(0, 3, 4)))
APP.append(after_table())

APP += appendix("ค", "รายการโปรแกรม")
APP.append(intro("โปรแกรมของระบบประกอบด้วยไฟล์ตามตารางภาคผนวกที่ ค.1 รายการโปรแกรมพร้อมคำอธิบาย (comment) แสดงในหัวข้อถัดไป"))
APP.append(caption_tbl("ตารางภาคผนวกที่ ค.1 ไฟล์โปรแกรมของระบบ"))
APP.append(table(["ไฟล์", "หน้าที่"], [
    ["collector/collector.py", "โปรแกรมหลัก รับเหตุการณ์ เรียกส่วนแปลงข้อมูลและส่วนตรวจจับ และเล่นเสียงแจ้งเตือน"],
    ["collector/normalize.py", "แปลงเหตุการณ์จาก eslogger เป็นฟิลด์กลางแบบ Sigma"],
    ["collector/store.py", "สร้างและบันทึกข้อมูลลงฐานข้อมูล SQLite"],
    ["engine/rules.py", "อ่านไฟล์กฎและเปรียบเทียบกฎกับเหตุการณ์"],
    ["dashboard/app.py", "Dashboard บน Streamlit"],
    ["dashboard/console/index.html", "component ที่แสดงหน้าจอ Dashboard โดยไม่ต้องโหลดหน้าเว็บใหม่"],
    ["scripts/report.py", "คำนวณตัวชี้วัดจากผลการทดสอบ"],
    ["attacksim/run_atomic.sh, baseline.sh", "รันชุดทดสอบ Atomic Red Team และบันทึกช่วงเวลา"],
    ["tests/test_rules.py", "ทดสอบกฎทั้งหมดด้วยเหตุการณ์จำลอง"],
], [3400, 4900]))
APP.append(after_table())
for f in ["collector/collector.py", "collector/normalize.py", "collector/store.py", "engine/rules.py", "dashboard/app.py",
          "dashboard/console/index.html", "scripts/report.py", "attacksim/run_atomic.sh"]:
    APP.append(h3(f))
    APP.append(draft("แทรกโค้ดฉบับสุดท้ายพร้อม comment หลังจบการปรับกฎด้วยชุด dev (ใช้ฟอนต์ความกว้างคงที่ ขนาด 10–11 point)"))

APP += appendix("ง", "ชุดทดสอบ Atomic Red Team ที่ใช้")
APP.append(intro(
    "ตารางภาคผนวกที่ ง.1 แสดงเทคนิคที่วางแผนทดสอบ แบ่งเป็นชุด dev ซึ่งใช้ปรับปรุงกฎ และชุด eval ซึ่งใช้วัดผล ทุกชุดเป็นชุดทดสอบทางการ"
    "ของ Red Canary ที่รองรับ macOS และรันคำสั่งคืนสภาพหลังทดสอบทุกครั้ง เทคนิค T1555.001 ไม่ได้รันแบบอัตโนมัติ เพราะชุดทดสอบบางชุด"
    "อาจเปิดเผยรหัสผ่านที่บันทึกไว้ในเครื่อง"))
NAMES = {"T1082": "System Information Discovery", "T1087.001": "Account Discovery: Local Account",
         "T1016": "System Network Configuration Discovery", "T1518.001": "Software Discovery: Security Software Discovery",
         "T1059.002": "Command and Scripting Interpreter: AppleScript", "T1059.004": "Command and Scripting Interpreter: Unix Shell",
         "T1543.001": "Create or Modify System Process: Launch Agent", "T1564.001": "Hide Artifacts: Hidden Files and Directories",
         "T1553.001": "Subvert Trust Controls: Gatekeeper Bypass", "T1070.003": "Indicator Removal: Clear Command History",
         "T1053.003": "Scheduled Task/Job: Cron", "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
         "T1140": "Deobfuscate/Decode Files or Information", "T1033": "System Owner/User Discovery", "T1057": "Process Discovery",
         "T1083": "File and Directory Discovery", "T1201": "Password Policy Discovery", "T1217": "Browser Information Discovery",
         "T1543.004": "Create or Modify System Process: Launch Daemon", "T1547.015": "Boot or Logon Autostart Execution: Login Items",
         "T1562.001": "Impair Defenses: Disable or Modify Tools", "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
         "T1569.001": "System Services: Launchctl", "T1059.006": "Command and Scripting Interpreter: Python",
         "T1105": "Ingress Tool Transfer"}
plan = [l.split() for l in open("/home/claude/md/attacksim/plan.txt", encoding="utf-8") if l.strip() and not l.startswith("#")]
APP.append(caption_tbl("ตารางภาคผนวกที่ ง.1 เทคนิคที่ใช้ทดสอบ"))
APP.append(table(["ลำดับ", "รหัสเทคนิค", "ชื่อเทคนิค", "ชุด", "ผล"],
                 [[str(i + 1), t, NAMES.get(t, ""), s, ""] for i, (t, s) in enumerate(plan)],
                 [750, 1550, 4100, 850, 1050], center_cols=(0, 1, 3, 4)))
APP.append(after_table())
APP.append(draft("เติมคอลัมน์ผลหลังทดสอบ (Detected / Visible-Not Detected / Not Visible / รันไม่สำเร็จ) และตรวจชื่อเทคนิคกับ ATT&CK v19"))

# ================================================================ ประวัติผู้เขียน
BIO = [sect_end(), title("ประวัติผู้เขียน", page_break=False).replace('w:before="0"', 'w:before="720"')]
BIO.append(plain_table([
    ["ชื่อ", "นายสหรัตน์ ทรัพย์แสง"],
    ["วัน เดือน ปีเกิด", [("วัน เดือน ปี พ.ศ. เกิด", True)]],
    ["สถานที่เกิด", [("จังหวัด ประเทศ", True)]],
    ["ประวัติการศึกษา", [("ระดับมัธยมปลาย ชื่อโรงเรียน, ปี พ.ศ. ที่จบ", True)]],
    ["", "ปริญญาวิศวกรรมศาสตรบัณฑิต สาขาวิชาวิศวกรรมคอมพิวเตอร์"],
    ["", [("วิทยาลัยวิศวกรรมศาสตร์ มหาวิทยาลัยรังสิต, คาดว่าจะสำเร็จการศึกษา ", False), ("เดือน ปี", True)]],
    ["ทุนการศึกษา/รางวัล", [("ถ้ามี ถ้าไม่มีให้ลบแถวนี้", True)]],
], [2600, 5700]))

# ================================================================ splice
doc = open(DOC, encoding="utf-8").read()
assert "ปริญญานิพนธ์เรื่อง" not in doc, "already inserted"
paras = list(re.finditer(r"<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>", doc, flags=re.S))


def ptext(m):
    return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", m.group(0)))


i_cover_end = next(i for i, m in enumerate(paras) if ptext(m).strip() == "ปีการศึกษา 2569")       # last line of cover
i_inner_end = next(i for i, m in enumerate(paras) if "<w:sectPr" in m.group(0))                 # inner cover ends section 1
body_sect = doc.rindex("<w:sectPr")
edits = [
    (paras[i_cover_end].end(), paras[i_cover_end].end(), "".join(APPROVAL)),
    (paras[i_inner_end].end(), paras[i_inner_end].end(), "".join(FRONT)),
    (body_sect, body_sect, "".join(CH5) + "".join(BIB) + "".join(APP) + "".join(BIO)),
]
for s, e, rep in sorted(edits, key=lambda x: -x[0]):
    doc = doc[:s] + rep + doc[e:]
HF = ('<w:headerReference w:type="default" r:id="rId15"/><w:headerReference w:type="first" r:id="rId13"/>'
      '<w:footerReference w:type="default" r:id="rId16"/><w:footerReference w:type="first" r:id="rId14"/>')
first = True


def fix_hf(m):
    global first
    if first:            # cover + inner cover keep their own headers
        first = False
        return m.group(0)
    x = re.sub(r'<w:(header|footer)Reference [^>]*/>', '', m.group(0))
    return re.sub(r'(<w:sectPr[^>]*>)', r'\1' + HF, x, count=1)


doc = re.sub(r'<w:sectPr[ >].*?</w:sectPr>', fix_hf, doc, flags=re.S)
open(DOC, "w", encoding="utf-8").write(doc)
open(RELS, "w", encoding="utf-8").write(rels)
print("ok")
