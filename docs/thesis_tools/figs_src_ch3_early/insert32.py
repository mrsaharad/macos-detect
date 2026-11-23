"""Insert section 3.2 (text + 2 figures) into the thesis docx, after the '3.2 ...' heading.
Usage: python3 insert32.py <unpacked_dir>
Removes the '[ร่าง: ...]' placeholder paragraph that directly follows the 3.2 heading, if present.
"""
import os, re, shutil, sys
from xml.sax.saxutils import escape
from PIL import Image

U = sys.argv[1]
DOC = os.path.join(U, "word/document.xml")
RELS = os.path.join(U, "word/_rels/document.xml.rels")
FIGS = [
    ("/tmp/claude-0/fig/รูปที่3.2_FlowChart_ระบบ.png", "image_ch3_fig32.png"),
    ("/tmp/claude-0/fig/รูปที่3.3_WorkFlow_ทดสอบ.png", "image_ch3_fig33.png"),
]
EMU = 914400
MAX_H_IN = 7.3

FONT = '<w:rFonts w:ascii="TH Sarabun New" w:hAnsi="TH Sarabun New" w:cs="TH Sarabun New"/>'
RPR = f'<w:rPr>{FONT}<w:sz w:val="32"/><w:szCs w:val="32"/><w:cs/><w:lang w:val="en-US"/></w:rPr>'
RPR_B = f'<w:rPr>{FONT}<w:b/><w:bCs/><w:sz w:val="32"/><w:szCs w:val="32"/><w:cs/><w:lang w:val="en-US"/></w:rPr>'


def body(text):
    """Body paragraph styled like chapter 2: left indent 0.5in, first-line tab, justified."""
    return (
        f'<w:p><w:pPr><w:spacing w:after="120"/><w:ind w:left="720"/><w:jc w:val="both"/>{RPR}</w:pPr>'
        f'<w:r>{RPR}<w:tab/></w:r><w:r>{RPR}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
    )


def h3(text):
    return (
        '<w:p><w:pPr><w:pStyle w:val="Heading3"/><w:rPr><w:lang w:val="en-US"/></w:rPr></w:pPr>'
        f'<w:r><w:rPr><w:bCs/><w:szCs w:val="32"/><w:cs/><w:lang w:val="en-US"/></w:rPr><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
    )


def figure(rid, name, w_px, h_px, docpr_id):
    h_in = MAX_H_IN
    w_in = h_in * w_px / h_px
    cx, cy = int(w_in * EMU), int(h_in * EMU)
    return (
        f'<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60"/><w:jc w:val="center"/>{RPR}</w:pPr>'
        f'<w:r><w:rPr>{FONT}<w:noProof/><w:lang w:val="en-US"/></w:rPr><w:drawing>'
        f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
        f'<wp:effectExtent l="0" t="0" r="0" b="0"/><wp:docPr id="{docpr_id}" name="{name}"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{docpr_id}" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
    )


def caption(text):
    return (
        f'<w:p><w:pPr><w:spacing w:after="240"/><w:jc w:val="center"/>{RPR_B}</w:pPr>'
        f'<w:r>{RPR_B}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'
    )


# ---------------- content ----------------
P = []
P.append(body(
    "หัวข้อนี้อธิบายลำดับการทำงานของระบบในสองมุม มุมแรกคือลำดับการทำงานของระบบตรวจจับตั้งแต่เริ่มรับข้อมูลจาก eslogger "
    "จนถึงการบันทึกการแจ้งเตือน ซึ่งแสดงในรูปแบบ Flow Chart ในหัวข้อ 3.2.1 มุมที่สองคือลำดับขั้นตอนการทดสอบและวัดผลระบบด้วยชุดทดสอบ "
    "Atomic Red Team ซึ่งแสดงในรูปแบบ Work Flow ในหัวข้อ 3.2.2"))

P.append(h3("3.2.1 Flow Chart การทำงานของระบบตรวจจับ"))
P.append(body(
    "การทำงานของระบบตรวจจับเริ่มจากผู้ใช้งานเปิด Terminal ที่ได้รับสิทธิ์ Full Disk Access แล้วรันคำสั่ง "
    "sudo eslogger exec fork create rename unlink | python collector/collector.py ซึ่งเรียกใช้ eslogger ด้วยสิทธิ์ผู้ดูแลระบบ "
    "และส่งผลลัพธ์ผ่านท่อเข้าสู่ Collector จากนั้น Rule Engine จะโหลดกฎตรวจจับทั้งหมดจากไฟล์ YAML เข้าสู่หน่วยความจำเพียงครั้งเดียว "
    "เมื่อเริ่มทำงาน เพื่อไม่ต้องอ่านไฟล์กฎซ้ำทุกครั้งที่มีเหตุการณ์เข้ามา ซึ่งจะเพิ่มระยะเวลาในการตรวจจับโดยไม่จำเป็น"))
P.append(body(
    "หลังจากนั้นระบบทำงานเป็นวงรอบ โดยอ่านข้อมูลจาก eslogger ครั้งละหนึ่งบรรทัด หากข้อมูลสิ้นสุด ซึ่งเกิดขึ้นเมื่ออ่านจากไฟล์ log "
    "จนครบ หรือผู้ใช้งานสั่งหยุดการทำงานด้วยการกด Control + C ระบบจะสิ้นสุดการทำงาน มิฉะนั้นระบบจะตรวจสอบว่าบรรทัดนั้นเป็นข้อมูล JSON "
    "หรือไม่ หากไม่ใช่จะข้ามไปอ่านบรรทัดถัดไป หากใช่ Collector จะแปลงข้อมูลเป็นโครงสร้างข้อมูลของ Python แล้วส่งต่อให้ Normalizer "
    "แปลงเป็น schema กลางและเติมค่า ParentImage จากตารางจับคู่หมายเลขโปรเซสกับโปรแกรม"))
P.append(body(
    "ในกรณีที่เหตุการณ์เป็นประเภท exec หรือ fork ซึ่งเป็นเหตุการณ์ที่ทำให้โปรเซสเปลี่ยนโปรแกรมหรือเกิดโปรเซสใหม่ Normalizer "
    "จะปรับปรุงตารางจับคู่ดังกล่าวหลังจากเติมค่า ParentImage ของเหตุการณ์ปัจจุบันแล้ว ลำดับนี้มีความสำคัญ เนื่องจากค่า ParentImage "
    "ของเหตุการณ์ต้องมาจากข้อมูลของโปรเซสแม่ที่บันทึกไว้ก่อนหน้า ไม่ใช่ข้อมูลของโปรแกรมใหม่ที่เพิ่งถูกรัน จากนั้นระบบบันทึกเหตุการณ์ลงตาราง "
    "events ในฐานข้อมูล"))
P.append(body(
    "ขั้นตอนต่อมา Rule Engine นำเหตุการณ์ไปเปรียบเทียบกับกฎทีละข้อ หากเหตุการณ์ตรงกับเงื่อนไขของกฎ ระบบจะสร้างการแจ้งเตือน "
    "พร้อมบันทึกเวลาที่สร้างการแจ้งเตือน (ts_alert) แล้วบันทึกลงตาราง alerts เหตุการณ์หนึ่งรายการอาจตรงกับกฎมากกว่าหนึ่งข้อ "
    "ซึ่งจะทำให้เกิดการแจ้งเตือนมากกว่าหนึ่งรายการ เมื่อเปรียบเทียบครบทุกกฎแล้ว ระบบจะกลับไปอ่านข้อมูลบรรทัดถัดไป ลำดับการทำงานทั้งหมด"
    "แสดงดังรูปที่ 3.2 ทั้งนี้ Dashboard ทำงานเป็นโปรแกรมแยกที่อ่านข้อมูลจากฐานข้อมูลเป็นระยะ จึงไม่ปรากฏในวงรอบนี้"))
P.append("@@FIG0@@")
P.append(caption("รูปที่ 3.2 Flow Chart การทำงานของระบบตรวจจับ"))

P.append(h3("3.2.2 Work Flow การทดสอบและวัดผลระบบ"))
P.append(body(
    "การทดสอบและวัดผลระบบเริ่มจากการเตรียมสภาพแวดล้อม โดยบันทึกเวอร์ชันของ macOS พร้อมหมายเลข build และเวอร์ชันของซอฟต์แวร์ที่ใช้ "
    "เนื่องจากรูปแบบผลลัพธ์ของ eslogger อาจเปลี่ยนแปลงระหว่างเวอร์ชันของระบบปฏิบัติการ ผลการทดสอบจึงใช้ได้กับเวอร์ชันที่ทดสอบเท่านั้น "
    "จากนั้นเริ่มระบบตรวจจับ และเริ่มเก็บค่าการใช้หน่วยประมวลผลกลางและหน่วยความจำของ eslogger และโปรแกรม Python ของระบบทุก 1 วินาที "
    "ตลอดช่วงการทดสอบ เพื่อใช้คำนวณภาระต่อทรัพยากรเครื่อง"))
P.append(body(
    "ขั้นตอนแรกของการทดสอบคือช่วงการใช้งานเครื่องตามปกติโดยไม่รันชุดทดสอบใด ๆ การแจ้งเตือนที่เกิดขึ้นในช่วงนี้ถือเป็นการแจ้งเตือนเท็จ "
    "(False Positive) และเหตุการณ์ที่ไม่ก่อให้เกิดการแจ้งเตือนถือเป็น True Negative ตามนิยามในตารางที่ 2.2 ข้อมูลช่วงนี้ใช้คำนวณ "
    "อัตราการแจ้งเตือนเท็จ และจำนวนการแจ้งเตือนเท็จต่อชั่วโมง"))
P.append(body(
    "ขั้นตอนถัดมาคือการรันชุดทดสอบ Atomic Red Team ทีละชุด โดยแบ่งชุดทดสอบออกเป็นสองกลุ่ม ได้แก่ ชุด dev ซึ่งใช้ระหว่างการพัฒนาเพื่อปรับปรุงกฎ "
    "และชุด eval ซึ่งใช้วัดผลจริงหลังจากกฎถูกกำหนดเป็นฉบับสุดท้ายแล้ว การแบ่งกลุ่มนี้ป้องกันไม่ให้กฎถูกปรับให้ตรงกับชุดทดสอบที่ใช้วัดผลโดยเฉพาะ "
    "ซึ่งจะทำให้ผลการวัดดีเกินจริง ก่อนรันแต่ละชุด ผู้จัดทำบันทึกเวลาเริ่มและรหัสเทคนิคตาม MITRE ATT&CK ของชุดนั้น หากชุดทดสอบทำงานไม่สำเร็จ "
    "จากปัจจัยแวดล้อม เช่น ขาดโปรแกรมที่จำเป็นหรือไม่มีสิทธิ์เพียงพอ จะบันทึกแยกไว้และไม่นำมาคำนวณ ตามหลักการที่กล่าวไว้ในหัวข้อ 2.3.4"))
P.append(body(
    "หากชุดทดสอบทำงานสำเร็จ จะตรวจสอบว่ามีการแจ้งเตือนที่สัมพันธ์กับเทคนิคนั้นภายในช่วงเวลาของการทดสอบหรือไม่ หากมีจะนับเป็น True Positive "
    "และจัดเทคนิคนั้นอยู่ในกลุ่มตรวจจับได้ (Detected) หากไม่มีจะนับเป็น False Negative แล้วตรวจสอบต่อในตาราง events ว่ามีเหตุการณ์ที่สะท้อน"
    "พฤติกรรมของชุดทดสอบนั้นหรือไม่ หากมี จะจัดอยู่ในกลุ่มมองเห็นแต่ไม่ได้ตรวจจับ (Visible, Not Detected) ซึ่งแก้ไขได้ด้วยการเพิ่มหรือปรับปรุงกฎ "
    "หากไม่มี จะจัดอยู่ในกลุ่มมองไม่เห็น (Not Visible) ซึ่งเป็น Visibility Gap ที่ต้องวิเคราะห์สาเหตุเชิงเทคนิค ขั้นตอนนี้เป็นเหตุผลที่ระบบออกแบบ"
    "ให้บันทึกเหตุการณ์ทั้งหมดลงตาราง events ไม่ใช่บันทึกเฉพาะการแจ้งเตือน เพราะหากไม่มีข้อมูลเหตุการณ์ จะไม่สามารถแยกสองกลุ่มหลังออกจากกันได้"))
P.append(body(
    "หลังตรวจสอบผลของแต่ละชุด จะรันคำสั่งคืนสภาพ (cleanup) ของชุดทดสอบเพื่อให้เครื่องกลับสู่สภาพเดิม แล้วจึงทดสอบชุดถัดไปจนครบ "
    "เมื่อทดสอบครบทุกชุดแล้ว จะคำนวณตัวชี้วัดตามสมการที่ (2.1) ถึง (2.5) จากข้อมูลในตาราง events และ alerts โดยระยะเวลาในการตรวจจับคำนวณจาก "
    "ผลต่างระหว่างเวลาที่สร้างการแจ้งเตือนกับเวลาที่เกิดเหตุการณ์ จากนั้นจัดกลุ่ม Visibility Gap และสร้างแผนที่ความครอบคลุมด้วย ATT&CK Navigator "
    "ขั้นตอนทั้งหมดแสดงดังรูปที่ 3.3 และผลการทดสอบจะนำเสนอในบทที่ 4"))
P.append("@@FIG1@@")
P.append(caption("รูปที่ 3.3 Work Flow การทดสอบและวัดผลระบบ"))

# ---------------- media + rels ----------------
rels = open(RELS, encoding="utf-8").read()
used = {int(x) for x in re.findall(r'Id="rId(\d+)"', rels)}
nxt = max(used) + 1
fig_xml = []
for i, (src, name) in enumerate(FIGS):
    shutil.copy(src, os.path.join(U, "word/media", name))
    rid = f"rId{nxt + i}"
    rels = rels.replace("</Relationships>",
        f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{name}"/></Relationships>')
    w, h = Image.open(src).size
    fig_xml.append(figure(rid, f"Figure 3.{2+i}", w, h, 913200 + i))
open(RELS, "w", encoding="utf-8").write(rels)

content = "".join(P).replace("@@FIG0@@", fig_xml[0]).replace("@@FIG1@@", fig_xml[1])

# ---------------- splice into document ----------------
doc = open(DOC, encoding="utf-8").read()
paras = list(re.finditer(r"<w:p[ >].*?</w:p>", doc, flags=re.S))
def ptext(m): return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", m.group(0)))

hidx = next((i for i, m in enumerate(paras) if ptext(m).strip().startswith("3.2 ") and "Heading2" in m.group(0)), None)
assert hidx is not None, "3.2 heading not found"
start = paras[hidx].end()
end = start
if hidx + 1 < len(paras) and ptext(paras[hidx + 1]).strip().startswith("[ร่าง"):
    end = paras[hidx + 1].end()
    print("removed placeholder after 3.2")
assert "image_ch3_fig32" not in doc, "3.2 already inserted"
doc = doc[:start] + content + doc[end:]
open(DOC, "w", encoding="utf-8").write(doc)
print("inserted 3.2:", len(content), "chars")
