"""Insert sections 3.3–3.5 (text, tables, figures) and chapter 4 headings into the thesis docx.
Usage: python3 insert3x.py <unpacked_dir>
"""
import os
import re
import shutil
import sys
from xml.sax.saxutils import escape

from PIL import Image

U = sys.argv[1]
DOC = os.path.join(U, "word/document.xml")
RELS = os.path.join(U, "word/_rels/document.xml.rels")
FIG = "/home/claude/thesis/figs/out"
SHOT = "/home/claude/thesis/shots/out"
EMU = 914400
MAX_W, MAX_H = 5.7, 7.6

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


# ---------------- figures ----------------
rels = open(RELS, encoding="utf-8").read()
_next_rid = [max(int(x) for x in re.findall(r'Id="rId(\d+)"', rels)) + 1]
_next_pic = [913300]


def figure(path, name, max_h=MAX_H):
    global rels
    media = f"image_ch3_{name}.png"
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


# ================================================================ 3.3
S33 = []
S33.append(intro(
    "หัวข้อนี้แสดงการไหลของข้อมูลในระบบด้วยแผนภาพกระแสข้อมูล (Data Flow Diagram: DFD) ตามสัญลักษณ์แบบ Gane และ Sarson "
    "ซึ่งใช้สี่เหลี่ยมมุมมนแทนกระบวนการ (process) สี่เหลี่ยมปลายเปิดด้านขวาแทนแหล่งเก็บข้อมูล (data store) และสี่เหลี่ยมที่มีเงาแทนสิ่งที่อยู่"
    "ภายนอกระบบ (external entity) โดยเริ่มจากภาพรวมระดับบนสุดคือ Context Diagram แล้วแตกรายละเอียดลงเป็น DFD ระดับที่ 1 "
    "ซึ่งแสดงกระบวนการหลักทั้งหมดของระบบ และ DFD ระดับที่ 2 ของกระบวนการตรวจจับ ซึ่งเป็นกระบวนการที่ซับซ้อนที่สุดของระบบ"))
S33.append(h3("3.3.1 Context Diagram"))
S33.append(body(
    "Context Diagram แสดงระบบทั้งหมดเป็นกระบวนการเดียว (กระบวนการที่ 0) และแสดงเฉพาะข้อมูลที่ไหลเข้าและออกระหว่างระบบกับสิ่งภายนอก "
    "ซึ่งมีทั้งหมด 4 สิ่ง ได้แก่ macOS Endpoint Security ซึ่งส่งข้อมูลเหตุการณ์ในรูปแบบ JSON ผ่าน eslogger เข้าสู่ระบบอย่างต่อเนื่อง "
    "ผู้พัฒนากฎตรวจจับ ซึ่งเขียนและปรับปรุงกฎในรูปแบบไฟล์ YAML ผู้วิเคราะห์ความปลอดภัย ซึ่งได้รับการแจ้งเตือน หลักฐาน และเสียงแจ้งเตือน "
    "จากระบบ และส่งผลการตัดสินว่าการแจ้งเตือนเป็นภัยจริงหรือไม่รวมถึงคำค้นหากลับเข้าสู่ระบบ และผู้ทดสอบระบบ ซึ่งส่งช่วงเวลาของการทดสอบ"
    "แต่ละชุดเข้าสู่ระบบในรูปแบบไฟล์ runs.csv และได้รับรายงานผลการวัดกลับไป ดังแสดงในรูปที่ 3.4"))
S33.append(body(
    "ชุดทดสอบ Atomic Red Team ไม่ปรากฏเป็นสิ่งภายนอกในแผนภาพนี้ เนื่องจากชุดทดสอบไม่ได้ส่งข้อมูลเข้าสู่ระบบโดยตรง แต่สร้างพฤติกรรม"
    "การโจมตีขึ้นบนเครื่อง ซึ่ง macOS จะรายงานพฤติกรรมนั้นเข้ามาในรูปของเหตุการณ์เช่นเดียวกับโปรแกรมอื่นทั่วไป ลักษณะนี้ทำให้การทดสอบ"
    "สะท้อนการทำงานจริงของระบบ เพราะระบบไม่ได้รับรู้ล่วงหน้าว่าเหตุการณ์ใดมาจากชุดทดสอบ"))
S33.append(figure(f"{FIG}/ctx.png", "fig34_context"))
S33.append(caption_fig("รูปที่ 3.4 Context Diagram ของระบบตรวจจับภัยคุกคามบน macOS"))

S33.append(h3("3.3.2 Data Flow Diagram ระดับที่ 1"))
S33.append(body(
    "DFD ระดับที่ 1 แตกกระบวนการที่ 0 ออกเป็น 5 กระบวนการตามส่วนประกอบของระบบในหัวข้อ 3.1 และแสดงแหล่งเก็บข้อมูล 5 แห่ง ได้แก่ "
    "D1 ตาราง events D2 ตาราง alerts D3 ไฟล์กฎตรวจจับ D4 ตาราง alert_verdicts และ D5 ไฟล์ runs.csv ดังแสดงในรูปที่ 3.5 "
    "กระบวนการที่ 1.0 รับข้อมูลเหตุการณ์จาก eslogger และคัดกรองเฉพาะบรรทัดที่เป็นข้อมูล JSON กระบวนการที่ 2.0 แปลงเหตุการณ์ให้อยู่ใน"
    "รูปแบบกลาง แล้วบันทึกลง D1 พร้อมส่งเหตุการณ์และหมายเลขอ้างอิงของเหตุการณ์ (event_id) ต่อให้กระบวนการที่ 3.0 ซึ่งนำเหตุการณ์ไป"
    "เปรียบเทียบกับกฎที่อ่านจาก D3 และบันทึกการแจ้งเตือนลง D2"))
S33.append(body(
    "กระบวนการที่ 4.0 คือ Dashboard ซึ่งอ่านข้อมูลจาก D1 D2 และ D3 เพื่อแสดงการแจ้งเตือนพร้อมหลักฐานแก่ผู้วิเคราะห์ความปลอดภัย และรับผล"
    "การตัดสินว่าการแจ้งเตือนแต่ละรายการเป็น True Positive หรือ False Positive บันทึกลง D4 ส่วนกระบวนการที่ 5.0 คือสคริปต์ประเมินผล "
    "report.py ซึ่งนำช่วงเวลาการทดสอบจาก D5 มาจับคู่กับข้อมูลใน D1 D2 และ D4 เพื่อคำนวณตัวชี้วัด แล้วส่งรายงานผลให้ผู้ทดสอบระบบ "
    "แหล่งเก็บข้อมูล D1 และ D2 ปรากฏซ้ำสองตำแหน่งในแผนภาพเพื่อลดการตัดกันของเส้น โดยตำแหน่งที่ซ้ำแสดงด้วยเส้นแนวตั้งเพิ่มที่ด้านซ้าย"))
S33.append(body(
    "จุดสำคัญของการออกแบบในระดับนี้คือกระบวนการที่ 3.0 กับ 4.0 ไม่ได้ส่งข้อมูลถึงกันโดยตรง แต่สื่อสารผ่านแหล่งเก็บข้อมูลเท่านั้น ทำให้ "
    "Dashboard หยุดทำงานหรือเปิดใหม่ได้โดยไม่กระทบการตรวจจับ นอกจากนี้ D4 ถูกแยกไปเก็บในไฟล์ฐานข้อมูลอีกไฟล์หนึ่ง (verdicts.db) "
    "เนื่องจากระหว่างการพัฒนาพบว่าเมื่อ Dashboard และส่วนตรวจจับเขียนข้อมูลลงไฟล์ฐานข้อมูลเดียวกันพร้อมกัน SQLite จะล็อกไฟล์และทำให้การ"
    "เขียนฝั่งใดฝั่งหนึ่งล้มเหลว การแยกไฟล์ทำให้ส่วนตรวจจับเป็นผู้เขียนเพียงรายเดียวของ D1 และ D2 ส่วน Dashboard เปิดไฟล์ดังกล่าวแบบ"
    "อ่านอย่างเดียว"))
S33.append(figure(f"{FIG}/l1.png", "fig35_dfd1"))
S33.append(caption_fig("รูปที่ 3.5 Data Flow Diagram ระดับที่ 1"))

S33.append(h3("3.3.3 Data Flow Diagram ระดับที่ 2 ของกระบวนการตรวจจับ"))
S33.append(body(
    "รูปที่ 3.6 แตกกระบวนการที่ 3.0 ออกเป็น 5 กระบวนการย่อย กระบวนการที่ 3.1 อ่านไฟล์กฎทั้งหมดจาก D3 และตรวจสอบรูปแบบของกฎ "
    "รวมถึงแยกวิเคราะห์ (parse) เงื่อนไขในส่วน condition ไว้ล่วงหน้า กระบวนการนี้ทำงานเพียงครั้งเดียวเมื่อระบบเริ่มทำงาน หากกฎข้อใดเขียน"
    "ผิดรูปแบบ ระบบจะแจ้งข้อผิดพลาดตั้งแต่ตอนเริ่ม แทนที่จะไปพบข้อผิดพลาดระหว่างตรวจจับ กระบวนการที่ 3.2 รับเหตุการณ์มาตรฐานจาก"
    "กระบวนการที่ 2.0 แล้วคัดเฉพาะกฎที่ใช้กับชนิดเหตุการณ์นั้น ตามความสัมพันธ์ระหว่าง logsource ของกฎกับชนิดเหตุการณ์ในตารางที่ 3.8 "
    "เช่น กฎของการสร้างไฟล์จะไม่ถูกนำไปเทียบกับเหตุการณ์ exec ซึ่งช่วยลดงานที่ไม่จำเป็น"))
S33.append(body(
    "กระบวนการที่ 3.3 เทียบเหตุการณ์กับ selection แต่ละกลุ่มของกฎ ได้ผลเป็นจริงหรือเท็จของแต่ละกลุ่ม แล้วกระบวนการที่ 3.4 นำผลเหล่านี้ไป"
    "ประเมินตามเงื่อนไขรวมในส่วน condition เช่น selection and not filter_system การประเมินเงื่อนไขใช้ตัวแยกวิเคราะห์ที่เขียนขึ้นเอง ไม่ได้ใช้"
    "คำสั่ง eval ของ Python เพื่อป้องกันไม่ให้ข้อความในไฟล์กฎถูกตีความเป็นคำสั่งโปรแกรม สุดท้ายกระบวนการที่ 3.5 สร้างการแจ้งเตือนสำหรับ"
    "ทุกกฎที่ตรงเงื่อนไข บันทึกลง D2 พิมพ์ข้อความ ALERT ลงหน้าต่าง Terminal และเล่นเสียงแจ้งเตือนตามระดับความรุนแรงสูงสุดของเหตุการณ์นั้น"))
S33.append(body(
    "เสียงแจ้งเตือนเล่นด้วยโปรแกรม afplay ที่มากับ macOS ไม่ได้ใช้ osascript ซึ่งเป็นวิธีแสดงการแจ้งเตือนของ macOS ที่พบได้ทั่วไป "
    "เพราะกฎ MD-0006 ตรวจจับการรัน osascript จากบรรทัดคำสั่ง หากระบบเรียก osascript เอง กฎจะตรวจพบการกระทำของระบบเองแล้วสร้าง"
    "การแจ้งเตือนต่อเนื่องเป็นวงไม่สิ้นสุด กระบวนการย่อยในระดับนี้มีขนาดเล็กพอที่จะสอดคล้องกับฟังก์ชันในโปรแกรมโดยตรง จึงไม่จำเป็นต้อง"
    "แตกรายละเอียดเป็น DFD ระดับที่ 3"))
S33.append(figure(f"{FIG}/l2.png", "fig36_dfd2"))
S33.append(caption_fig("รูปที่ 3.6 Data Flow Diagram ระดับที่ 2 ของกระบวนการตรวจจับ (กระบวนการที่ 3.0)"))

# ================================================================ 3.4
W4 = [1950, 1550, 950, 3850]
S34 = []
S34.append(intro(
    "ระบบเก็บข้อมูลในสองรูปแบบ รูปแบบแรกคือฐานข้อมูล SQLite ได้แก่ ไฟล์ data/detect.db ซึ่งมีตาราง events และ alerts และไฟล์ "
    "data/verdicts.db ซึ่งมีตาราง alert_verdicts SQLite เหมาะกับระบบนี้เพราะเก็บทั้งฐานข้อมูลไว้ในไฟล์เดียว ไม่ต้องติดตั้งเซิร์ฟเวอร์ และ"
    "เรียกใช้ได้ด้วยไลบรารี sqlite3 ที่มากับ Python ระบบเปิดใช้โหมด Write-Ahead Logging (WAL) ซึ่งทำให้ Dashboard อ่านข้อมูลได้ในขณะที่"
    "ส่วนตรวจจับกำลังเขียนข้อมูล และบันทึกข้อมูลทันทีทีละรายการ (autocommit) เพื่อไม่ให้ส่วนตรวจจับถือสิทธิ์การเขียนค้างไว้ระหว่างรอ"
    "เหตุการณ์ถัดไป รูปแบบที่สองคือไฟล์กฎตรวจจับในรูปแบบ YAML ซึ่งแยกไฟล์ละหนึ่งกฎในโฟลเดอร์ rules"))
S34.append(h3("3.4.1 ER Diagram"))
S34.append(body(
    "ความสัมพันธ์ระหว่างข้อมูลแสดงด้วย ER Diagram ตามสัญลักษณ์แบบ Crow's Foot ในรูปที่ 3.7 เหตุการณ์หนึ่งรายการในตาราง events "
    "อาจไม่ก่อให้เกิดการแจ้งเตือนเลย หรือก่อให้เกิดการแจ้งเตือนได้หลายรายการ เนื่องจากเหตุการณ์เดียวอาจตรงกับกฎมากกว่าหนึ่งข้อ เช่น "
    "คำสั่ง osascript ที่เปิดหน้าต่างหลอกถามรหัสผ่านจะตรงกับทั้งกฎ MD-0004 และ MD-0006 ความสัมพันธ์ระหว่าง events กับ alerts จึงเป็น"
    "แบบหนึ่งต่อศูนย์หรือหลาย ในทำนองเดียวกัน กฎหนึ่งข้อสร้างการแจ้งเตือนได้หลายรายการ ส่วนการแจ้งเตือนหนึ่งรายการมีผลการตัดสินได้"
    "ไม่เกินหนึ่งรายการ ความสัมพันธ์ระหว่าง alerts กับ alert_verdicts จึงเป็นแบบหนึ่งต่อศูนย์หรือหนึ่ง"))
S34.append(body(
    "กฎตรวจจับแสดงด้วยกรอบเส้นประ เพราะเก็บเป็นไฟล์ YAML ไม่ใช่ตารางในฐานข้อมูล ฟิลด์ rule_id ในตาราง alerts จึงอ้างอิงถึงรหัสกฎ"
    "ในไฟล์ โดยไม่มีข้อบังคับ Foreign Key ในระดับฐานข้อมูล นอกจากนี้ตาราง alerts ยังเก็บชื่อกฎ ระดับความรุนแรง ยุทธวิธี และเทคนิค ณ เวลา"
    "ที่เกิดการแจ้งเตือนไว้ด้วย แม้ข้อมูลเหล่านี้จะหาได้จากไฟล์กฎ การเก็บซ้ำนี้ตั้งใจให้การแจ้งเตือนในอดีตยังคงแสดงข้อมูลตามกฎฉบับที่ใช้"
    "ตรวจจับจริงในขณะนั้น แม้ภายหลังกฎจะถูกแก้ไขระหว่างการปรับปรุงด้วยชุดทดสอบ dev"))
S34.append(figure(f"{FIG}/er.png", "fig37_er"))
S34.append(caption_fig("รูปที่ 3.7 ER Diagram ของข้อมูลในระบบ"))

S34.append(h3("3.4.2 Data Dictionary"))
S34.append(body(
    "รายละเอียดของฟิลด์ในแต่ละตารางแสดงในตารางที่ 3.3 ถึงตารางที่ 3.5 เวลาทั้งหมดในฐานข้อมูลเก็บเป็นข้อความตามมาตรฐาน ISO 8601 "
    "ในเขตเวลา UTC เพื่อหลีกเลี่ยงความคลาดเคลื่อนจากเขตเวลา และแปลงเป็นเวลาประเทศไทยเฉพาะตอนแสดงผลบน Dashboard ฟิลด์ที่ตั้งชื่อ"
    "ตามแนวทางของ Sigma เช่น Image และ CommandLine ใช้ตัวพิมพ์ใหญ่นำหน้าเพื่อให้ตรงกับชื่อฟิลด์ที่ใช้ในไฟล์กฎ"))
S34.append(caption_tbl("ตารางที่ 3.3 Data Dictionary ของตาราง events"))
S34.append(table(["ชื่อฟิลด์", "ชนิดข้อมูล", "คีย์", "คำอธิบาย"], [
    ["id", "INTEGER", "PK", "ลำดับของเหตุการณ์ เพิ่มค่าอัตโนมัติ"],
    ["ts_event", "TEXT", "", "เวลาที่เหตุการณ์เกิดขึ้นตามที่ eslogger รายงาน"],
    ["ts_ingest", "TEXT", "", "เวลาที่ระบบรับเหตุการณ์เข้ามา"],
    ["event_type", "TEXT", "", "ชนิดเหตุการณ์ ได้แก่ exec, fork, create, rename และ unlink"],
    ["pid", "INTEGER", "", "หมายเลขโปรเซส (สำหรับ fork คือโปรเซสลูกที่เกิดใหม่)"],
    ["ppid", "INTEGER", "", "หมายเลขโปรเซสแม่"],
    ["Image", "TEXT", "", "เส้นทางเต็มของโปรแกรมที่ทำให้เกิดเหตุการณ์"],
    ["ParentImage", "TEXT", "", "เส้นทางของโปรแกรมแม่ ได้จากตารางจับคู่ในหน่วยความจำ ว่างได้หากโปรเซสแม่เริ่มก่อนระบบ"],
    ["CommandLine", "TEXT", "", "คำสั่งพร้อมอาร์กิวเมนต์ (เฉพาะเหตุการณ์ exec)"],
    ["TargetFilename", "TEXT", "", "ไฟล์ปลายทาง (เหตุการณ์ create, rename และ unlink)"],
    ["SourceFilename", "TEXT", "", "ไฟล์ต้นทางก่อนเปลี่ยนชื่อ (เหตุการณ์ rename)"],
    ["SigningId", "TEXT", "", "รหัสลายเซ็นของโปรแกรม เช่น com.apple.sw_vers"],
    ["User", "INTEGER", "", "หมายเลขผู้ใช้ที่มีผลจริง (euid) โดย 0 หมายถึง root"],
], W4, center_cols=(1, 2)))
S34.append(after_table())
S34.append(caption_tbl("ตารางที่ 3.4 Data Dictionary ของตาราง alerts"))
S34.append(table(["ชื่อฟิลด์", "ชนิดข้อมูล", "คีย์", "คำอธิบาย"], [
    ["id", "INTEGER", "PK", "ลำดับของการแจ้งเตือน เพิ่มค่าอัตโนมัติ"],
    ["event_id", "INTEGER", "FK", "อ้างอิง events.id ของเหตุการณ์ที่เป็นหลักฐาน"],
    ["rule_id", "TEXT", "", "รหัสกฎที่ตรวจพบ เช่น MD-0011 (อ้างอิงไฟล์กฎ)"],
    ["title", "TEXT", "", "ชื่อกฎ ณ เวลาที่เกิดการแจ้งเตือน"],
    ["level", "TEXT", "", "ระดับความรุนแรง ได้แก่ critical, high, medium และ low"],
    ["tactic", "TEXT", "", "ยุทธวิธีตาม MITRE ATT&CK เช่น persistence"],
    ["technique", "TEXT", "", "รหัสเทคนิคตาม MITRE ATT&CK เช่น T1543.001"],
    ["plain_th", "TEXT", "", "คำอธิบายภาษาไทยแบบเข้าใจง่ายของกฎ"],
    ["ts_event", "TEXT", "", "เวลาที่เหตุการณ์เกิดขึ้น คัดลอกจาก events เพื่อคำนวณระยะเวลาในการตรวจจับ"],
    ["ts_alert", "TEXT", "", "เวลาที่ระบบสร้างการแจ้งเตือน"],
], W4, center_cols=(1, 2)))
S34.append(after_table())
S34.append(caption_tbl("ตารางที่ 3.5 Data Dictionary ของตาราง alert_verdicts"))
S34.append(table(["ชื่อฟิลด์", "ชนิดข้อมูล", "คีย์", "คำอธิบาย"], [
    ["alert_id", "INTEGER", "PK, FK", "อ้างอิง alerts.id ของการแจ้งเตือนที่ถูกตัดสิน"],
    ["verdict", "TEXT", "", "ผลการตัดสิน ได้แก่ tp (True Positive) และ fp (False Positive)"],
    ["note", "TEXT", "", "บันทึกเพิ่มเติมของผู้วิเคราะห์"],
    ["ts", "TEXT", "", "เวลาที่บันทึกผลการตัดสิน"],
], W4, center_cols=(1, 2)))
S34.append(after_table())
S34.append(body(
    "ข้อมูลตัวแปรสภาพแวดล้อม (environment variables) ที่ eslogger รายงานมาพร้อมเหตุการณ์ exec จะไม่ถูกจัดเก็บในตารางใดเลย "
    "เนื่องจากอาจมีข้อมูลส่วนบุคคล เช่น เส้นทางในเครื่องของผู้ใช้และค่าที่ใช้ยืนยันตัวตนของโปรแกรมอื่น"))

S34.append(h3("3.4.3 โครงสร้างไฟล์กฎตรวจจับ"))
S34.append(body(
    "กฎตรวจจับแต่ละข้อเป็นไฟล์ YAML หนึ่งไฟล์ ตั้งชื่อตามรหัสกฎ เช่น MD-0011.yml โครงสร้างของไฟล์ดัดแปลงจากรูปแบบของ Sigma "
    "โดยเพิ่มฟิลด์ภาษาไทยสำหรับใช้อ้างอิงในเอกสาร ฟิลด์ทั้งหมดแสดงในตารางที่ 3.6 และตัวอย่างไฟล์กฎแสดงในรูปที่ 3.8"))
S34.append(caption_tbl("ตารางที่ 3.6 ฟิลด์ในไฟล์กฎตรวจจับ"))
S34.append(table(["ฟิลด์", "ความหมาย"], [
    ["id", "รหัสกฎในรูปแบบ MD-xxxx"],
    ["title", "ชื่อกฎภาษาอังกฤษ ใช้แสดงบน Dashboard"],
    ["title_th", "ชื่อกฎภาษาไทย ใช้อ้างอิงในเอกสาร"],
    ["description", "คำอธิบายภาษาอังกฤษว่าพฤติกรรมนี้คืออะไร และทำไมจึงน่าสงสัย"],
    ["plain_th", "คำอธิบายภาษาไทยแบบเข้าใจง่าย"],
    ["status", "สถานะของกฎ (experimental)"],
    ["tags", "ยุทธวิธีและเทคนิคตาม MITRE ATT&CK เช่น attack.persistence และ attack.t1543.001"],
    ["logsource", "แพลตฟอร์ม (macos) และประเภทข้อมูล (category) ซึ่งกำหนดชนิดเหตุการณ์ที่กฎใช้"],
    ["detection", "กลุ่มเงื่อนไข selection หรือ filter อย่างน้อยหนึ่งกลุ่ม และ condition"],
    ["falsepositives", "กรณีการใช้งานปกติที่อาจทำให้กฎแจ้งเตือนผิด"],
    ["level", "ระดับความรุนแรง ได้แก่ critical, high, medium และ low"],
], [2000, 6300]))
S34.append(after_table())
S34.append(body(
    "ภายในกลุ่มเงื่อนไขหนึ่งกลุ่ม ทุกฟิลด์ต้องตรงกันพร้อมกัน (AND) และหากค่าของฟิลด์เป็นรายการ ค่าใดค่าหนึ่งในรายการตรงก็เพียงพอ (OR) "
    "วิธีเทียบค่ากำหนดด้วยตัวปรับ (modifier) ต่อท้ายชื่อฟิลด์ ซึ่งระบบรองรับตามตารางที่ 3.7 การเทียบทุกแบบไม่สนใจความแตกต่างระหว่าง"
    "ตัวพิมพ์เล็กกับตัวพิมพ์ใหญ่ตามมาตรฐานของ Sigma"))
S34.append(caption_tbl("ตารางที่ 3.7 ตัวปรับ (modifier) ที่ระบบรองรับ"))
S34.append(table(["Modifier", "ความหมาย", "เทียบได้กับ SQL"], [
    ["(ไม่ระบุ)", "ค่าต้องเท่ากันทุกตัวอักษร", "= 'x'"],
    ["contains", "มีข้อความนี้อยู่ตำแหน่งใดก็ได้", "LIKE '%x%'"],
    ["startswith", "ขึ้นต้นด้วยข้อความนี้", "LIKE 'x%'"],
    ["endswith", "ลงท้ายด้วยข้อความนี้", "LIKE '%x'"],
    ["re", "ตรงกับ regular expression", "-"],
    ["all", "ทุกค่าในรายการต้องตรง (เปลี่ยน OR เป็น AND)", "-"],
], [1900, 4300, 2100], center_cols=(2,)))
S34.append(after_table())
S34.append(caption_tbl("ตารางที่ 3.8 ความสัมพันธ์ระหว่าง logsource ของกฎกับชนิดเหตุการณ์"))
S34.append(table(["category ใน logsource", "ชนิดเหตุการณ์ที่ใช้", "ตัวอย่างกฎ"], [
    ["process_creation", "exec", "MD-0001 ถึง MD-0010"],
    ["process_fork", "fork", "-"],
    ["file_event", "create, rename", "MD-0011, MD-0012, MD-0014"],
    ["file_rename", "rename", "-"],
    ["file_delete", "unlink", "MD-0018"],
], [2800, 2600, 2900], center_cols=(1,)))
S34.append(after_table())
S34.append(listing([
    "id: MD-0011",
    "title: Launch agent created",
    "title_th: สร้างไฟล์ .plist ใน LaunchAgents (เปิดเองตอนล็อกอิน)",
    "description: A new .plist in LaunchAgents makes a program start",
    "  every time the user logs in.",
    "tags:",
    "- attack.persistence",
    "- attack.t1543.001",
    "logsource:",
    "  product: macos",
    "  category: file_event",
    "detection:",
    "  selection:",
    "    TargetFilename|contains: /Library/LaunchAgents/",
    "    TargetFilename|endswith: .plist",
    "  condition: selection",
    "falsepositives:",
    "- การติดตั้งแอปที่มีตัวช่วยเบื้องหลัง",
    "level: high",
]))
S34.append(caption_fig("รูปที่ 3.8 ตัวอย่างไฟล์กฎ MD-0011 (ตัดฟิลด์ status, plain_th และ author ออกเพื่อความกระชับ)"))
S34.append(body(
    "กฎในรูปที่ 3.8 ตรวจจับการสร้างไฟล์ .plist ในโฟลเดอร์ LaunchAgents ซึ่งทำให้โปรแกรมเปิดขึ้นเองทุกครั้งที่ผู้ใช้เข้าสู่ระบบ และเป็นวิธี"
    "ฝังตัวที่มัลแวร์บน macOS ใช้บ่อย กฎใช้ category เป็น file_event จึงถูกนำไปเทียบกับเหตุการณ์ create และ rename เท่านั้น และกลุ่ม "
    "selection กำหนดให้เส้นทางไฟล์ต้องมีข้อความ /Library/LaunchAgents/ และลงท้ายด้วย .plist พร้อมกัน"))

S34.append(h3("3.4.4 Flow Chart การเทียบกฎกับเหตุการณ์"))
S34.append(body(
    "รูปที่ 3.9 แสดงขั้นตอนของโปรแกรมเมื่อได้รับเหตุการณ์มาตรฐานหนึ่งรายการ ซึ่งเป็นรายละเอียดของขั้นตอนการเปรียบเทียบกับกฎในรูปที่ 3.2 "
    "ระบบหยิบกฎทีละข้อ ตรวจสอบก่อนว่าชนิดเหตุการณ์ตรงกับ logsource ของกฎหรือไม่ หากไม่ตรงจะข้ามกฎนั้นทันที หากตรงจะเทียบแต่ละ"
    "กลุ่ม selection แล้วประเมิน condition หากผลเป็นจริงจะบันทึกการแจ้งเตือนลงตาราง alerts และพิมพ์ข้อความลงหน้าต่าง Terminal "
    "เมื่อเทียบครบทุกกฎแล้ว หากเหตุการณ์นี้ทำให้เกิดการแจ้งเตือนอย่างน้อยหนึ่งรายการ ระบบจะเล่นเสียงตามระดับความรุนแรงสูงสุดเพียงครั้งเดียว "
    "และเว้นระยะห่างจากเสียงครั้งก่อนอย่างน้อย 2 วินาที เพื่อไม่ให้เสียงดังซ้อนกันเมื่อมีการแจ้งเตือนจำนวนมากในเวลาใกล้กัน"))
S34.append(figure(f"{FIG}/flow.png", "fig39_flow"))
S34.append(caption_fig("รูปที่ 3.9 Flow Chart การเทียบกฎกับเหตุการณ์"))

# ================================================================ 3.5
S35 = []
S35.append(intro(
    "Dashboard ออกแบบให้ผู้วิเคราะห์ตอบคำถามหลักสามข้อได้อย่างรวดเร็ว ได้แก่ เกิดอะไรขึ้นบนเครื่องบ้าง เกิดขึ้นเมื่อใด และร้ายแรงเพียงใด "
    "ผู้จัดทำออกแบบต้นแบบหน้าจอ (mockup) ด้วยเครื่องมือ Claude Design ก่อน เพื่อทดลองการจัดวางและขนาดของส่วนประกอบ แล้วจึงพัฒนาจริงด้วย "
    "Streamlit โดยวาดหน้าจอด้วย HTML และ CSS ที่เขียนเองทั้งหมดภายใน component ของ Streamlit ซึ่งทำให้เปลี่ยนหน้าหรือเลือกการแจ้งเตือน"
    "ได้โดยไม่ต้องโหลดหน้าเว็บใหม่ ข้อความบนหน้าจอใช้ภาษาอังกฤษ เนื่องจากคำศัพท์ด้านความมั่นคงปลอดภัยส่วนใหญ่เป็นภาษาอังกฤษ และสอดคล้อง"
    "กับเครื่องมือที่ใช้งานจริงในศูนย์ปฏิบัติการด้านความมั่นคงปลอดภัย (Security Operations Center: SOC)"))
S35.append(h3("3.5.1 Site Map"))
S35.append(body(
    "Dashboard ประกอบด้วย 4 หน้า ซึ่งเข้าถึงได้จากเมนูด้านซ้ายของทุกหน้า ดังแสดงในรูปที่ 3.10 หน้า Overview แสดงภาพรวมของการตรวจจับ "
    "และรีเฟรชข้อมูลเองทุก 3 วินาที หน้า Alerts ใช้ตรวจสอบการแจ้งเตือนทีละรายการและบันทึกผลการตัดสิน หน้า Event search ใช้ค้นหา"
    "เหตุการณ์ทั้งหมดที่ระบบเก็บไว้ ซึ่งจำเป็นต่อการวิเคราะห์ Visibility Gap และหน้า Rules & ATT&CK แสดงกฎทั้งหมดและความครอบคลุม"
    "ตาม MITRE ATT&CK หน้าที่มีช่องค้นหาจะไม่รีเฟรชเอง เพื่อไม่ให้ข้อความที่ผู้ใช้กำลังพิมพ์หายไป และมีปุ่ม Refresh ให้กดเมื่อต้องการ"
    "ข้อมูลล่าสุดแทน"))
S35.append(figure(f"{FIG}/site.png", "fig310_site"))
S35.append(caption_fig("รูปที่ 3.10 Site Map ของ Dashboard"))
S35.append(h3("3.5.2 หลักการออกแบบหน้าจอ"))
S35.append(body(
    "หน้าจอใช้พื้นสีเข้มเพื่อลดความล้าของสายตาเมื่อเปิดเฝ้าดูเป็นเวลานาน และใช้สีเฉพาะเพื่อสื่อระดับความรุนแรงตามตารางที่ 3.9 เท่านั้น "
    "ส่วนอื่นของหน้าจอใช้สีเทาเป็นหลัก เพื่อให้สีของการแจ้งเตือนเด่นที่สุดบนหน้าจอ ทุกจุดที่ใช้สีจะมีข้อความชื่อระดับกำกับไว้ด้วย ผู้ที่แยกสีได้"
    "ยากจึงยังอ่านระดับความรุนแรงได้ ตัวอักษรใช้ฟอนต์ Sarabun ซึ่งเป็นฟอนต์ที่เผยแพร่ภายใต้สัญญาอนุญาต SIL Open Font License และใช้"
    "ฟอนต์ความกว้างคงที่ (JetBrains Mono) เฉพาะกับคำสั่ง เส้นทางไฟล์ และรหัสต่าง ๆ เพื่อให้อ่านอักขระได้ถูกต้อง"))
S35.append(caption_tbl("ตารางที่ 3.9 สีและความหมายของระดับความรุนแรง"))
S35.append(table(["ระดับ", "สี", "ความหมาย", "ตัวอย่างกฎ"], [
    ["Critical", "แดง (#F2555A)", "ระบบป้องกันของเครื่องถูกปิด ต้องตรวจสอบทันที", "MD-0020 ปิด Gatekeeper"],
    ["High", "ส้ม (#F08C3C)", "พฤติกรรมที่มักเป็นส่วนหนึ่งของการโจมตีโดยตรง", "MD-0011 สร้าง Launch agent"],
    ["Medium", "เหลือง (#D6B23B)", "พฤติกรรมที่น่าสงสัย แต่โปรแกรมปกติก็ทำได้", "MD-0006 รัน osascript -e"],
    ["Low", "ฟ้า (#6D9BD8)", "การสำรวจข้อมูลเครื่อง ซึ่งผู้โจมตีมักทำก่อนขั้นอื่น", "MD-0022 เรียก sw_vers"],
], [1300, 1800, 3100, 2100], center_cols=(0,)))
S35.append(after_table())

S35.append(h3("3.5.3 หน้า Overview"))
S35.append(body(
    "หน้า Overview ในรูปที่ 3.11 เริ่มด้วยแถบสรุปตัวเลข 4 ช่อง ได้แก่ จำนวนการแจ้งเตือนแยกตามระดับความรุนแรง จำนวนการแจ้งเตือนที่ยัง"
    "รอการตรวจ จำนวนเหตุการณ์ที่เก็บไว้พร้อมอัตราเหตุการณ์ต่อนาที และค่ากลางของระยะเวลาในการตรวจจับ ส่วนถัดมาคือแถบการแจ้งเตือน"
    "ตามเวลา ซึ่งแบ่งเป็น 4 เลนตามระดับความรุนแรง และแสดงการแจ้งเตือนแต่ละรายการเป็นขีดตามเวลาที่เกิด ผู้ใช้เลือกช่วงเวลาได้ 15 นาที "
    "1 ชั่วโมง 6 ชั่วโมง และ 24 ชั่วโมง การแยกเลนทำให้เห็นได้ทันทีว่าช่วงใดมีการแจ้งเตือนระดับสูงหนาแน่นผิดปกติ ส่วนล่างของหน้าแสดง"
    "การแจ้งเตือนล่าสุด 7 รายการ และจำนวนการแจ้งเตือนแยกตามยุทธวิธีของ MITRE ATT&CK ทั้ง 6 ยุทธวิธีที่ระบบครอบคลุม "
    "ยุทธวิธีที่ยังไม่มีการแจ้งเตือนจะแสดงเป็นศูนย์ ไม่ถูกตัดออก เพื่อให้เห็นภาพรวมครบทุกยุทธวิธี แถบด้านซ้ายล่างแสดงสถานะของส่วน"
    "ตรวจจับ ซึ่งจะเปลี่ยนเป็น Collector stopped เมื่อไม่มีเหตุการณ์ใหม่เข้ามาเกิน 30 วินาที"))
S35.append(body(
    "ภาพหน้าจอในรูปที่ 3.11 ถึงรูปที่ 3.14 ใช้ชุดเหตุการณ์ทดสอบที่ป้อนเข้าส่วนตรวจจับโดยตรงโดยไม่ผ่าน eslogger เพื่อแสดงหน้าจอ"
    "ขณะมีการแจ้งเตือนครบทุกระดับ ค่า Detection latency ในภาพจึงเกือบเป็นศูนย์ ซึ่งต่ำกว่าเมื่อใช้งานจริง จากการทดลองเบื้องต้นบน"
    "เครื่องจริง ระยะเวลาในการตรวจจับอยู่ที่ประมาณ 210 ถึง 250 มิลลิวินาที ผลการวัดจริงจะนำเสนอในบทที่ 4"))
S35.append(figure(f"{SHOT}/overview.png", "fig311_overview"))
S35.append(caption_fig("รูปที่ 3.11 หน้า Overview (ข้อมูลจากชุดเหตุการณ์ทดสอบ)"))
S35.append(h3("3.5.4 หน้า Alerts"))
S35.append(body(
    "หน้า Alerts ในรูปที่ 3.12 แบ่งเป็นสองส่วน ด้านซ้ายคือรายการการแจ้งเตือนเรียงจากล่าสุด ซึ่งกรองได้ด้วยช่องค้นหา ปุ่มระดับความรุนแรง "
    "และสถานะการตรวจ ด้านขวาคือรายละเอียดของการแจ้งเตือนที่เลือก ประกอบด้วยชื่อและคำอธิบายของกฎ รหัสกฎ รหัสเทคนิคและยุทธวิธี "
    "ลำดับโปรเซส (process tree) ซึ่งไล่ย้อนจากโปรเซสที่ทำให้เกิดการแจ้งเตือนขึ้นไปหาโปรเซสแม่จากข้อมูลในตาราง events และหลักฐาน "
    "เช่น คำสั่ง ไฟล์ ผู้ใช้ รหัสลายเซ็น และระยะเวลาในการตรวจจับ ส่วนล่างสุดคือปุ่ม True positive และ False positive สำหรับบันทึกผลการ"
    "ตัดสินลงตาราง alert_verdicts ผลการตัดสินนี้นำไปใช้คำนวณค่า Precision ในบทที่ 4"))
S35.append(figure(f"{SHOT}/alerts.png", "fig312_alerts"))
S35.append(caption_fig("รูปที่ 3.12 หน้า Alerts และรายละเอียดการแจ้งเตือน (ข้อมูลจากชุดเหตุการณ์ทดสอบ)"))
S35.append(h3("3.5.5 หน้า Event search"))
S35.append(body(
    "หน้า Event search ในรูปที่ 3.13 ค้นหาเหตุการณ์ทั้งหมดในตาราง events ด้วยข้อความในชื่อโปรแกรม โปรแกรมแม่ คำสั่ง หรือเส้นทางไฟล์ "
    "และกรองตามชนิดเหตุการณ์ได้ หน้านี้แสดงผลล่าสุด 300 รายการ หน้านี้มีบทบาทสำคัญในการทดสอบ เพราะเมื่อชุดทดสอบใดไม่ทำให้เกิด"
    "การแจ้งเตือน ผู้ทดสอบจะใช้หน้านี้ตรวจว่าระบบมองเห็นพฤติกรรมนั้นหรือไม่ เพื่อจัดชุดทดสอบเข้ากลุ่ม Visible, Not Detected หรือ "
    "Not Visible ตามขั้นตอนในหัวข้อ 3.2.2"))
S35.append(figure(f"{SHOT}/events.png", "fig313_events"))
S35.append(caption_fig("รูปที่ 3.13 หน้า Event search (ข้อมูลจากชุดเหตุการณ์ทดสอบ)"))
S35.append(h3("3.5.6 หน้า Rules & ATT&CK"))
S35.append(body(
    "หน้า Rules & ATT&CK ในรูปที่ 3.14 แสดงตารางความครอบคลุม ซึ่งจัดรหัสเทคนิคของกฎทุกข้อเป็นคอลัมน์ตามยุทธวิธี เทคนิคที่เคยตรวจพบแล้ว"
    "จะแสดงด้วยพื้นสีแดงพร้อมจำนวนครั้ง ทำให้เห็นได้ว่ากฎข้อใดยังไม่เคยทำงานเลย ด้านล่างเป็นตารางกฎทั้งหมดพร้อมชื่อ คำอธิบาย ระดับ"
    "ความรุนแรง ยุทธวิธี เทคนิค และจำนวนครั้งที่ตรวจพบ ข้อมูลในหน้านี้อ่านจากไฟล์กฎโดยตรง เมื่อเพิ่มหรือแก้ไขกฎ หน้านี้จึงแสดงข้อมูล"
    "ตามไฟล์ล่าสุดเสมอ"))
S35.append(figure(f"{SHOT}/rules.png", "fig314_rules"))
S35.append(caption_fig("รูปที่ 3.14 หน้า Rules & ATT&CK (ข้อมูลจากชุดเหตุการณ์ทดสอบ)"))

# ================================================================ บทที่ 4
SECT = ('<w:sectPr><w:pgSz w:w="11900" w:h="16840"/><w:pgMar w:top="2160" w:right="1440" w:bottom="1440" w:left="2160" '
        'w:header="1417" w:footer="680" w:gutter="0"/><w:cols w:space="708"/><w:titlePg/><w:docGrid w:linePitch="360"/></w:sectPr>')
TITLE_RPR = (f'<w:rPr>{FONT}<w:b/><w:bCs/><w:color w:val="000000"/><w:sz w:val="36"/><w:szCs w:val="36"/><w:cs/></w:rPr>')
CH4 = []
CH4.append(f'<w:p><w:pPr><w:spacing w:after="0"/>{RPR}{SECT}</w:pPr></w:p>')   # จบ section บทที่ 3 (ขึ้นหน้าใหม่)
CH4.append(f'<w:p><w:pPr><w:spacing w:before="720" w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>'
           f'{run("บทที่ 4", TITLE_RPR)}</w:p>')
CH4.append(f'<w:p><w:pPr><w:spacing w:after="360" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/>{TITLE_RPR}</w:pPr>'
           f'{run("ผลการดำเนินงานและการวิเคราะห์ผล", TITLE_RPR)}</w:p>')
CH4.append(draft("บทนำสั้น ๆ ว่าบทนี้นำเสนอผลการพัฒนาระบบและผลการทดสอบตามวัตถุประสงค์ข้อ 1–4 ในหัวข้อ 1.2 ตามขั้นตอนในหัวข้อ 3.2.2"))
for title, note in [
    ("4.1 สภาพแวดล้อมการทดสอบ",
     "ตารางฮาร์ดแวร์และซอฟต์แวร์: MacBook Air M2 RAM 8 GB, macOS 27.2 (26B123), Python 3.14, eslogger, PowerShell และ "
     "Invoke-AtomicRedTeam (ระบุเวอร์ชัน), จำนวนกฎ 25 ข้อ, วันที่และระยะเวลาทดสอบ และระบุว่าผลใช้ได้กับเวอร์ชันที่ทดสอบ"),
    ("4.2 ผลการพัฒนาระบบ",
     "ระบบต้นแบบที่ทำงานได้จริง ภาพหน้าจอจากข้อมูลจริงบนเครื่อง ตัวอย่างการแจ้งเตือนจริง และ False Positive ที่พบระหว่างพัฒนา "
     "เช่น sw_vers ที่ถูกเรียกโดยแอปอื่นและโดย Dashboard รุ่นแรก ซึ่งตรงกับกฎ MD-0022"),
    ("4.3 ผลการทดสอบการตรวจจับด้วย Atomic Red Team",
     "ตารางผลรายเทคนิคแยกชุด dev และ eval, Detection Rate และ Coverage ตามสมการในบทที่ 2 และแผนที่ความครอบคลุมจาก ATT&CK Navigator"),
    ("4.4 ผลการวัดการแจ้งเตือนเท็จ",
     "จำนวนการแจ้งเตือนเท็จต่อชั่วโมงจากช่วงใช้งานเครื่องตามปกติ, False Positive Rate และ Precision จากผลการตัดสินบน Dashboard"),
    ("4.5 ผลการวัดระยะเวลาในการตรวจจับ",
     "ค่ากลาง เปอร์เซ็นไทล์ที่ 95 และค่าสูงสุดของ ts_alert − ts_event พร้อมกราฟการกระจาย"),
    ("4.6 ผลการวัดภาระต่อทรัพยากรเครื่อง",
     "การใช้หน่วยประมวลผลกลางและหน่วยความจำของ eslogger และ collector ทุก 1 วินาที และอัตราเหตุการณ์ต่อวินาที"),
    ("4.7 การวิเคราะห์ Visibility Gap",
     "จัดเทคนิคที่ทดสอบเป็น 3 กลุ่ม Detected, Visible-Not Detected และ Not Visible พร้อมสาเหตุเชิงเทคนิคของแต่ละรายการ"),
    ("4.8 สรุปผลการทดสอบเทียบกับวัตถุประสงค์",
     "ตารางเทียบวัตถุประสงค์ 4 ข้อกับผลที่ได้ และระบุว่าบรรลุหรือไม่"),
]:
    CH4.append(h2(title))
    CH4.append(draft(note))

# ================================================================ splice
doc = open(DOC, encoding="utf-8").read()
assert "image_ch3_fig34_context" not in doc, "already inserted"
paras = list(re.finditer(r"<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>", doc, flags=re.S))


def ptext(m):
    return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", m.group(0)))


def find(prefix, style="Heading2"):
    return next(i for i, m in enumerate(paras) if ptext(m).strip().startswith(prefix) and style in m.group(0))


def retitle(m, new):
    x = m.group(0)
    first = True

    def sub(t):
        nonlocal first
        if first:
            first = False
            return f'<w:t xml:space="preserve">{escape(new)}</w:t>'
        return "<w:t></w:t>"
    return re.sub(r"<w:t[^>]*>[^<]*</w:t>", sub, x)


def rewrite_para(m, new_text):
    """keep pPr and first run's rPr, replace all runs with one run"""
    x = m.group(0)
    ppr = re.search(r"<w:pPr>.*?</w:pPr>", x, re.S).group(0)
    rpr = re.search(r"<w:r>(<w:rPr>.*?</w:rPr>)", x, re.S).group(1)
    head = x[:x.index(">") + 1]
    return f'{head}{ppr}<w:r>{rpr}<w:t xml:space="preserve">{escape(new_text)}</w:t></w:r></w:p>'


i33, i34, i35 = find("3.3 "), find("3.4 "), find("3.5 ")
edits = []   # (start, end, replacement) applied back-to-front

# fix 3.1 paragraphs that still say the Dashboard shows Thai descriptions
for i, m in enumerate(paras):
    t = ptext(m)
    if t.startswith("เมื่อเหตุการณ์ตรงกับเงื่อนไขของกฎใด Rule Engine"):
        new = t.replace("กฎแต่ละข้อยังมีฟิลด์คำอธิบายภาษาไทยที่เข้าใจง่าย สำหรับใช้แสดงผลบน Dashboard",
                        "กฎแต่ละข้อยังมีชื่อและคำอธิบายแบบเข้าใจง่าย ทั้งภาษาอังกฤษสำหรับแสดงผลบน Dashboard และภาษาไทยสำหรับใช้อ้างอิงในเอกสาร")
        assert new != t
        edits.append((m.start(), m.end(), rewrite_para(m, new)))
    if t.startswith("Dashboard พัฒนาด้วย Streamlit"):
        new = t.replace("รายการการแจ้งเตือนพร้อมคำอธิบายภาษาไทยและหลักฐาน", "รายการการแจ้งเตือนพร้อมคำอธิบายที่เข้าใจง่ายและหลักฐาน")
        assert new != t
        edits.append((m.start(), m.end(), rewrite_para(m, new)))

# 3.3: retitle heading, replace placeholder with content
m = paras[i33]
edits.append((m.start(), paras[i33 + 1].end(), retitle(m, "3.3 Context Diagram และ Data Flow Diagram") + "".join(S33)))
m = paras[i34]
edits.append((m.start(), paras[i34 + 1].end(), retitle(m, "3.4 ER Diagram, Data Dictionary และ Flow Chart ของโปรแกรม") + "".join(S34)))
m = paras[i35]
assert ptext(paras[i35 + 1]).startswith("[ร่าง")
edits.append((m.start(), paras[i35 + 1].end(), retitle(m, "3.5 การออกแบบหน้าจอ Dashboard และ Site Map") + "".join(S35) + "".join(CH4)))

for s, e, rep in sorted(edits, key=lambda x: -x[0]):
    doc = doc[:s] + rep + doc[e:]
open(DOC, "w", encoding="utf-8").write(doc)
open(RELS, "w", encoding="utf-8").write(rels)
print("ok, edits:", len(edits))
