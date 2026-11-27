"""แก้จากการตรวจเล่มทั้งเล่ม (27 พ.ย. 2569)
1. รูปที่ 3.2 แสดงภาพ Work Flow (ไฟล์ media/image12.png ถูกเขียนทับเมื่อ 23 พ.ย.) และรูปที่ 3.3 ไม่มีภาพ
   → คืนภาพ Flow Chart ของระบบตรวจจับ (figs/out/fig32_detection_flow.png จากไฟล์สำรอง 22 พ.ย.)
   → ใส่ภาพ Work Flow (figs/out/fig33_workflow_v2.png) เหนือคำบรรยายรูปที่ 3.3
2. หัวข้อ 4.1 / ตารางที่ 4.1 มีแต่สภาพแวดล้อมของรุ่นที่ 1 → เพิ่มรุ่นที่ 2
3. หน้าว่างหลังหน้าอนุมัติ (ย่อหน้าตัวแบ่งหน้าล้นหน้า) → ใช้ pageBreakBefore ที่ปกในแทน
4. 3.1.7 ชี้ไปหัวข้อ 3.6.3 สำหรับการป้องกันตัวเองของรุ่นที่ 2
5. 1.5 บอกว่าการดำเนินงานจริงเร็วกว่าแผน
6. "Atomic test" → "Atomic Test", "กฎของ v2" → "กฎของรุ่นที่ 2" (เฉพาะเนื้อหา ไม่แตะโค้ดในภาคผนวก ค)"""
import html
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402

FIGS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "figs", "out"))
T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())


def app(prefix, extra):
    m = E.para(prefix)
    E.put(m, T.rewrite_para(m, html.unescape(T.ptext(m)) + " " + extra))


# ---------- 1. รูปที่ 3.2 และ 3.3 ----------
m = re.search(r'<w:p[ >](?:(?!</w:p>).)*?<wp:docPr id="913200" name="Figure 3.2"/>.*?</w:p>', E.doc, re.S)
rid = re.search(r'r:embed="(rId\d+)"', m.group(0)).group(1)
target = re.search(rf'Id="{rid}"[^>]*Target="([^"]+)"|Target="([^"]+)"[^>]*Id="{rid}"', T.rels)
target = target.group(1) or target.group(2)
assert target == "media/image12.png", target
assert E.doc.count(f'r:embed="{rid}"') == 1, "image12 ถูกใช้ที่อื่นด้วย"
shutil.copy(os.path.join(FIGS, "fig32_detection_flow.png"), os.path.join(T.U, "word", target))
cx, cy = 4005072, 6675120          # ขนาดเดิมของรูปที่ 3.2 (ภาพ 2160 x 3600)
g = re.sub(r'<wp:extent cx="\d+" cy="\d+"/>', f'<wp:extent cx="{cx}" cy="{cy}"/>', m.group(0))
g = re.sub(r'<a:ext cx="\d+" cy="\d+"/>', f'<a:ext cx="{cx}" cy="{cy}"/>', g)
E.doc = E.doc[:m.start()] + g + E.doc[m.end():]

cap = E.para("รูปที่ 3.3 Work Flow การทดสอบและวัดผลระบบ")
prev = E.doc.rfind("<w:p", 0, cap.start())
assert "<w:drawing" not in E.doc[prev:cap.start()]
E.doc = E.doc[:cap.start()] + T.figure(os.path.join(FIGS, "fig33_workflow_v2.png"), "fig33_workflow", max_h=7.3) \
    + E.doc[cap.start():]

# ---------- 2. หัวข้อ 4.1 ----------
E.rewrite("การทดสอบทั้งหมดทำบนเครื่องเดียวกับที่ใช้พัฒนาระบบ",
          "การทดสอบทั้งหมดทำบนเครื่องเดียวกับที่ใช้พัฒนาระบบ ระบบรุ่นที่ 1 ทดสอบในวันที่ 22 พฤศจิกายน 2569 และระบบรุ่นที่ 2 "
          "ทดสอบระหว่างวันที่ 23–27 พฤศจิกายน 2569 รายละเอียดของสภาพแวดล้อมแสดงดังตารางที่ 4.1 "
          "ผลการทดสอบใช้ได้กับเวอร์ชันของระบบปฏิบัติการและซอฟต์แวร์ในตารางนี้เท่านั้น")
SAME = "เหมือนรุ่นที่ 1"
rows = [
    ("เครื่อง", "MacBook Air M2, RAM 8 GB, SSD 256 GB", SAME),
    ("ระบบปฏิบัติการ", "macOS 27.2 (build 26B123)", SAME),
    ("แหล่งข้อมูล", "eslogger 1 โปรเซส รับเหตุการณ์ exec, fork, exit, create, rename และ unlink",
     "eslogger 2 โปรเซส เพิ่ม close, truncate, setflags, setextattr, deleteextattr และ btm_launch_item_add"),
    ("การทำงานของ collector", "เปิดใน Terminal ด้วยสิทธิ์ผู้ใช้", "LaunchDaemon สิทธิ์ root"),
    ("ภาษาและไลบรารี", "Python 3.14.3, PyYAML 6.0.3, Streamlit 1.66.1",
     "collector ใช้ Python 3.9.6 ของระบบ และ PyYAML 6.0.3 ส่วน Dashboard และสคริปต์วัดผลเหมือนรุ่นที่ 1"),
    ("เครื่องมือทดสอบ",
     "PowerShell 7.7.0, Invoke-AtomicRedTeam และชุด atomics ที่ติดตั้งวันที่ 22 พฤศจิกายน 2569 (355 เทคนิค)",
     "เหมือนรุ่นที่ 1 แต่รันทีละ test ด้วย run_atomic.sh"),
    ("กฎตรวจจับ", "26 กฎ ครอบคลุม 6 ยุทธวิธี (ล็อกกฎก่อนเริ่มชุด eval)",
     "33 กฎ ครอบคลุม 6 ยุทธวิธี (ล็อกกฎก่อนเริ่มชุด eval2)"),
    ("ช่วงเวลาทดสอบ",
     "ชุด dev ช่วงบ่าย ชุด eval 16.30–16.40 น. และ baseline 16.58–17.58 น. ของวันที่ 22 พฤศจิกายน 2569",
     "ชุด dev และ evasion 23 พ.ย., ชุด eval2 และ stress 24 พ.ย., baseline 24 และ 26 พ.ย., "
     "ทดสอบต่อเนื่อง 24 ชั่วโมง 25–26 พ.ย. 2569"),
]
E.table_after("ตารางที่ 4.1 สภาพแวดล้อมการทดสอบ",
              T.table(["รายการ", "รุ่นที่ 1", "รุ่นที่ 2"], rows, [1900, 3200, 3200]))

# ---------- 3. หน้าว่างหลังหน้าอนุมัติ ----------
i = E.doc.index("ตรวจชื่อหัวหน้าหลักสูตรปัจจุบันกับภาควิชา")
e = E.doc.index("</w:p>", i) + len("</w:p>")
br = '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
assert E.doc[e:e + len(br)] == br, E.doc[e:e + 80]
nxt = e + len(br)
ppr = E.doc.index("<w:pPr>", nxt)
assert ppr < E.doc.index("</w:p>", nxt) and "<w:drawing" in E.doc[nxt:E.doc.index("</w:p>", nxt)]
E.doc = E.doc[:e] + E.doc[nxt:ppr + len("<w:pPr>")] + "<w:pageBreakBefore/>" + E.doc[ppr + len("<w:pPr>"):]

# ---------- 4. 3.1.7 ----------
app("สิ่งที่อยู่นอกขอบเขต ได้แก่ ผู้โจมตีที่ตั้งใจปิดหรือหลบระบบตรวจจับเอง",
    "ระบบรุ่นที่ 2 แก้ข้อจำกัดเรื่องการถูกปิดหรือแก้ไขด้วยสิทธิ์ผู้ใช้ทั่วไป โดยทำงานเป็น LaunchDaemon สิทธิ์ root "
    "ตามหัวข้อ 3.6.3")

# ---------- 5. 1.5 ----------
app("การดำเนินโครงงานแบ่งออกเป็น 5 ขั้นตอน",
    "ในการดำเนินงานจริง การพัฒนาและทดสอบระบบทั้งสองรุ่นเสร็จในเดือนพฤศจิกายน 2569 ซึ่งเร็วกว่าแผน "
    "ผลการทดสอบในบทที่ 4 จึงเป็นผลจากวันที่ 22–27 พฤศจิกายน 2569")

# ---------- 6. คำ ----------
code_start = E.doc.index("ตารางภาคผนวกที่ ค.1 ไฟล์โปรแกรมของระบบ")
head, tail = E.doc[:code_start], E.doc[code_start:]
n1, n2 = head.count("Atomic test"), head.count("กฎของ v2")
assert (n1, n2) == (4, 1), (n1, n2)
E.doc = head.replace("Atomic test", "Atomic Test").replace("กฎของ v2", "กฎของรุ่นที่ 2") + tail

T.write_doc(E.doc)
T.save_rels()
