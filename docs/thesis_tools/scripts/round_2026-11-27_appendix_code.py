"""ภาคผนวก ค: ใส่โค้ดฉบับเต็มพร้อม comment ของทุกไฟล์ (คู่มือ: "ต้องใส่ Code Program และ Comments ลงในภาคผนวก")
โค้ดอ่านจากไฟล์ในโปรเจกต์ตอนรันสคริปต์ และระบุ commit ล่าสุดที่แก้ไฟล์เหล่านี้
รูปแบบ: Courier New 10 pt พื้นเทา เป็นย่อหน้าต่อเนื่อง (ไม่ใช้ตาราง เพื่อให้แบ่งหน้าได้เอง)"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402
from thesislib import escape  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FILES = [
    ("collector/collector.py", "โปรแกรมหลัก เปิด eslogger 2 โปรเซส รับเหตุการณ์ เรียกส่วนแปลงข้อมูลและส่วนตรวจจับ "
                               "บันทึก heartbeat และเล่นเสียงแจ้งเตือน"),
    ("collector/normalize.py", "แปลงเหตุการณ์จาก eslogger เป็นฟิลด์กลางแบบ Sigma รวมฟิลด์ลายเซ็นและฟิลด์ของรุ่นที่ 2"),
    ("collector/redact.py", "ปิดรหัสผ่านและ token ในคำสั่งก่อนเก็บ"),
    ("collector/store.py", "สร้างและบันทึกข้อมูลลงฐานข้อมูล SQLite"),
    ("engine/rules.py", "อ่านไฟล์กฎและเปรียบเทียบกฎกับเหตุการณ์"),
    ("engine/incidents.py", "รวมการแจ้งเตือนที่เกี่ยวข้องกันเป็น incident"),
    ("dashboard/app.py", "Dashboard บน Streamlit"),
    ("dashboard/console/index.html", "component ที่แสดงหน้าจอ Dashboard โดยไม่ต้องโหลดหน้าเว็บใหม่"),
    ("scripts/report.py", "คำนวณตัวชี้วัดจากผลการทดสอบ"),
    ("scripts/measure_overhead.py", "วัดการใช้ CPU และหน่วยความจำของ collector และ eslogger"),
    ("scripts/compare_sigmahq.py", "เปรียบเทียบกฎของโครงงานกับกฎ SigmaHQ บนข้อมูลชุดเดียวกัน"),
    ("attacksim/run_atomic.sh", "รันชุดทดสอบ Atomic Red Team ทีละ test และบันทึกช่วงเวลา"),
    ("attacksim/baseline.sh", "บันทึกช่วงใช้งานเครื่องตามปกติพร้อมวัดภาระต่อเครื่อง"),
    ("attacksim/stability.sh", "ทดสอบการทำงานต่อเนื่อง 24 ชั่วโมง"),
    ("attacksim/manual_tests.sh", "ทดสอบด้วยมือสำหรับเทคนิคที่ไม่มี Atomic Test บน macOS"),
    ("attacksim/evasion.py", "ทดสอบความทนทานต่อการหลบเลี่ยง"),
    ("attacksim/stress.py", "ทดสอบภายใต้ภาระสูงและผลกระทบต่อความเร็วของงานอื่น (A/B)"),
    ("attacksim/select_eval2.py", "คัดเลือกชุดทดสอบ eval2 แบบทำซ้ำได้"),
    ("deploy/install_daemon.sh", "ติดตั้ง collector เป็น LaunchDaemon"),
    ("deploy/uninstall_daemon.sh", "ถอนการติดตั้ง LaunchDaemon"),
    ("tests/test_rules.py", "ทดสอบกฎทั้งหมดด้วยเหตุการณ์จำลอง"),
]
commit = subprocess.run(["git", "-C", ROOT, "log", "-1", "--format=%h", "--"] + [f for f, _ in FILES],
                        capture_output=True, text=True, check=True).stdout.strip()

T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())

# ---------- ตารางภาคผนวกที่ ค.1 ----------
E.rewrite("โปรแกรมของระบบประกอบด้วยไฟล์ตามตารางภาคผนวกที่ ค.1",
          f"โปรแกรมของระบบประกอบด้วยไฟล์ตามตารางภาคผนวกที่ ค.1 รายการโปรแกรมพร้อมคำอธิบาย (comment) แสดงในหัวข้อถัดไป "
          f"โค้ดทั้งหมดเป็นฉบับเดียวกับ commit {commit} ของโปรเจกต์ ซึ่งเป็นฉบับที่ใช้วัดผลระบบรุ่นที่ 2")
E.table_after("ตารางภาคผนวกที่ ค.1 ไฟล์โปรแกรมของระบบ", T.table(["ไฟล์", "หน้าที่"], FILES, [3400, 4900]))

# ---------- รายการโปรแกรม ----------
SHADE = '<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>'
# TH Sarabun ที่ 10 pt เล็กกว่าตัวอังกฤษมาก ใช้ 14 pt เฉพาะตัวอักษรไทย (szCs) ให้ comment อ่านได้
CODE = T.MONO.replace('<w:szCs w:val="20"/>', '<w:szCs w:val="28"/>')


def heading(path):
    return (f'<w:p><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="60"/>{T.RPR_B}</w:pPr>'
            f'{T.run(path, T.RPR_B)}</w:p>')


def code(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        lines = f.read().expandtabs(4).rstrip("\n").split("\n")
    out = []
    for ln in lines:
        # บรรทัดยาวตัดขึ้นบรรทัดใหม่เอง ใช้ hanging indent ให้เห็นว่าเป็นบรรทัดเดียวกัน
        out.append(f'<w:p><w:pPr>{SHADE}<w:spacing w:after="0" w:line="240" w:lineRule="auto"/>'
                   f'<w:ind w:left="400" w:hanging="240"/>{CODE}</w:pPr>'
                   f'<w:r>{CODE}<w:t xml:space="preserve">{escape(ln) if ln else ""}</w:t></w:r></w:p>')
    return "".join(out)


listing = "".join(heading(p) + code(p) for p, _ in FILES)

doc = E.doc
tbl_end = doc.index("</w:tbl>", doc.index("ตารางภาคผนวกที่ ค.1 ไฟล์โปรแกรมของระบบ"))
first = doc.rfind("<w:p>", 0, doc.index(">collector/collector.py<", tbl_end))
# ช่วงที่แทนที่: หัวข้อไฟล์เดิม + ย่อหน้า [ร่าง: แทรกโค้ด...] ทั้งหมด จนถึงย่อหน้าที่มี section break ก่อนภาคผนวก ง
last_draft = doc.rfind("[ร่าง: แทรกโค้ดฉบับสุดท้ายพร้อม comment")
end = doc.index("</w:p>", last_draft) + len("</w:p>")
old = doc[first:end]
assert old.count("[ร่าง: แทรกโค้ด") == 10 and "<w:sectPr" not in old and "ภาคผนวก ง" not in old, old.count("[ร่าง")
E.doc = doc[:first] + listing + doc[end:]
T.write_doc(E.doc)
print(f"commit {commit}, {sum(1 for _ in FILES)} ไฟล์", file=sys.stderr)
