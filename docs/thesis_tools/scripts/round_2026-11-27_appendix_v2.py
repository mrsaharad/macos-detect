"""ภาคผนวก ก (คู่มือติดตั้ง/ใช้งาน) และ ข (ตารางกฎ) ให้ตรงกับรุ่นที่ 2
ที่มา: deploy/install_daemon.sh, deploy/uninstall_daemon.sh, attacksim/*.sh|py (บรรทัดวิธีใช้),
      scripts/compare_sigmahq.py --v2, rules/MD-0027..MD-0033.yml, tests/test_rules.py (33 ข้อ ผิด 0)"""
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402
from thesislib import escape  # noqa: E402

T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())


def app(prefix, extra):
    m = E.para(prefix)
    E.put(m, T.rewrite_para(m, html.unescape(T.ptext(m)) + " " + extra))


def code_block(lines):
    """กล่องโค้ดรูปแบบเดียวกับภาคผนวก ก เดิม (ตาราง 1 ช่อง พื้นเทา Courier New 10 pt)"""
    tpl = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*git clone https://github.com.*?</w:tbl>", E.doc, re.S).group(0)
    head = tpl[:tpl.index("<w:p>")]
    para = re.search(r"<w:p>.*?</w:p>", tpl, re.S).group(0)
    paras = "".join(re.sub(r"<w:t[^>]*>[^<]*</w:t>", f'<w:t xml:space="preserve">{escape(ln)}</w:t>', para, count=1)
                    for ln in lines)
    return head + paras + "</w:tc></w:tr></w:tbl>"


DB = '"/Library/Application Support/macdetect/data/detect.db"'

# ---------- ก.1 ความต้องการ ----------
app("เครื่อง Mac ที่ใช้ macOS 13 ขึ้นไป",
    "หากติดตั้งแบบรุ่นที่ 2 (LaunchDaemon) ต้องให้สิทธิ์ Full Disk Access กับ /usr/bin/python3 ของระบบด้วย "
    "เพราะ collector ทำงานด้วย Python ของระบบ ไม่ใช่ผ่าน Terminal")

# ---------- ก.2 การติดตั้ง ----------
E.sub("คำสั่งสุดท้ายทดสอบกฎทั้งหมดด้วยเหตุการณ์จำลอง", "กฎทั้งหมด 26 ข้อ", "กฎทั้งหมด 33 ข้อ")

# ---------- ก.3 การเริ่มใช้งาน ----------
E.rewrite("ดับเบิลคลิกไฟล์ start_collector.command",
          "ระบบรุ่นที่ 2 ติดตั้งส่วนเก็บข้อมูลเป็น LaunchDaemon ด้วยคำสั่งด้านล่าง ระบบจะเริ่มทำงานทันที เริ่มเองทุกครั้งที่เปิดเครื่อง "
          "และ launchd จะเปิดใหม่หากหยุดทำงาน โค้ด กฎ และฐานข้อมูลถูกคัดลอกไปไว้ที่ /Library/Application Support/macdetect "
          "การเปิด Dashboard ต้องระบุตำแหน่งฐานข้อมูลนี้ด้วยตัวแปร DETECT_DB แล้วเปิดเบราว์เซอร์ที่ http://localhost:8501 "
          "หากแก้กฎในโฟลเดอร์ rules ต้องรันคำสั่งติดตั้งซ้ำเพื่อคัดลอกกฎใหม่")
m = E.para("ระบบรุ่นที่ 2 ติดตั้งส่วนเก็บข้อมูลเป็น LaunchDaemon")
v2_start = (code_block([
    "sudo ./deploy/install_daemon.sh      # ติดตั้งและเริ่มทำงาน",
    'DB="/Library/Application Support/macdetect/data/detect.db"',
    "source .venv/bin/activate",
    'DETECT_DB="$DB" streamlit run dashboard/app.py',
    "sudo ./deploy/uninstall_daemon.sh    # ถอนการติดตั้ง",
]) + T.after_table()
    + T.rewrite_para(m, "หากต้องการรันแบบรุ่นที่ 1 ให้ดับเบิลคลิกไฟล์ start_collector.command ในโฟลเดอร์โปรเจกต์ แล้วกรอก"
                        "รหัสผ่านของเครื่อง จากนั้นดับเบิลคลิกไฟล์ start_dashboard.command หากต้องการหยุดการทำงาน ให้กด "
                        "Control + C ในหน้าต่าง Terminal ของแต่ละส่วน ข้อมูลของรุ่นที่ 1 เก็บอยู่ในโฟลเดอร์ data"))
E.doc = E.doc[:m.end()] + v2_start + E.doc[m.end():]

# ---------- ก.4 การทดสอบของรุ่นที่ 2 ----------
t = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*python scripts/report\.py.*?</w:tbl>", E.doc, re.S)
m_tpl = E.para("ติดตั้ง PowerShell และ Invoke-AtomicRedTeam")
v2_tests = (T.after_table()
            + T.rewrite_para(m_tpl, "การทดสอบระบบรุ่นที่ 2 ใช้คำสั่งต่อไปนี้ ทุกคำสั่งที่อ่านผลจากฐานข้อมูลต้องตั้งตัวแปร "
                                    "DETECT_DB เป็นฐานข้อมูลของ LaunchDaemon ต้องล็อกกฎก่อนรันชุด eval2 และรัน ab --state off "
                                    "หลังหยุด LaunchDaemon ชั่วคราว")
            + code_block([
                'DB="/Library/Application Support/macdetect/data/detect.db"',
                'export DETECT_DB="$DB"',
                "ART_SET=dev-v2 ./attacksim/run_atomic.sh dev",
                "./attacksim/run_atomic.sh eval2",
                "python attacksim/evasion.py --version v2",
                "python attacksim/stress.py stress --version v2",
                "python attacksim/stress.py ab --version v2 --state on",
                "python attacksim/stress.py ab --version v2 --state off",
                "TAG=stability_v2 ./attacksim/stability.sh 1440",
                "TAG=overhead_v2 SET=baseline2 ./attacksim/baseline.sh 480",
                "python scripts/compare_sigmahq.py --v2",
            ]))
E.doc = E.doc[:t.end()] + v2_tests + E.doc[t.end():]

# ---------- ภาคผนวก ข ----------
E.rewrite("ตารางภาคผนวกที่ ข.1 สรุปกฎตรวจจับทั้ง 26 ข้อ",
          "ตารางภาคผนวกที่ ข.1 สรุปกฎตรวจจับทั้ง 33 ข้อ กฎ MD-0001 ถึง MD-0026 ใช้ในรุ่นที่ 1 และกฎ MD-0027 ถึง MD-0033 "
          "เพิ่มในรุ่นที่ 2 ส่วนกฎ MD-0001, MD-0002, MD-0006, MD-0019 และ MD-0026 ปรับเงื่อนไขในรุ่นที่ 2 ตามหัวข้อ 3.6 "
          "ไฟล์กฎฉบับเต็มอยู่ในโฟลเดอร์ rules ของโปรเจกต์ ตามโครงสร้างในหัวข้อ 3.4.3")
new_rules = [
    ("MD-0027", "ซ่อนไฟล์ด้วย file flag (ตรวจจากเหตุการณ์ setflags)", "ซ่อนร่องรอย", "T1564.001", "Medium"),
    ("MD-0028", "ลบป้ายกักกัน (quarantine) ออกจากไฟล์ (ตรวจจากเหตุการณ์ deleteextattr)", "ซ่อนร่องรอย", "T1553.001",
     "High"),
    ("MD-0029", "macOS ลงทะเบียน Login Item, LaunchAgent หรือ LaunchDaemon ใหม่", "ฝังตัวถาวร",
     "T1543.001, T1543.004, T1547.015", "Medium"),
    ("MD-0030", "ล้างไฟล์ประวัติคำสั่งจนว่าง (ตรวจจากขนาดไฟล์หลังแก้)", "ซ่อนร่องรอย", "T1070.003", "Medium"),
    ("MD-0031", "แก้ไฟล์ตั้งค่า shell ที่มีอยู่แล้ว", "ฝังตัวถาวร", "T1546.004", "Low"),
    ("MD-0032", "โปรแกรมเซ็นแบบ ad-hoc แต่อ้างชื่อลายเซ็นของ Apple", "ซ่อนร่องรอย", "T1036", "High"),
    ("MD-0033", "รันโปรแกรมที่เซ็นแบบ ad-hoc จากโฟลเดอร์ cache หรือโฟลเดอร์ชั่วคราว", "ซ่อนร่องรอย", "T1036", "Medium"),
]
tbl = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*>MD-0026<.*?</w:tbl>", E.doc, re.S)
rows = re.findall(r"<w:tr[ >].*?</w:tr>", tbl.group(0), re.S)
last = rows[-1]
assert ">MD-0026<" in last
cells = re.findall(r"<w:tc>.*?</w:tc>", last, re.S)


def fill(cell, text):
    return re.sub(r"<w:t[^>]*>[^<]*</w:t>", f'<w:t xml:space="preserve">{escape(text)}</w:t>', cell, count=1)


assert all(len(re.findall(r"<w:t[ >]", c)) == 1 for c in cells), "แต่ละช่องของแถว MD-0026 ต้องมีข้อความ 1 run"
added = "".join(last[:last.index("<w:tc>")] + "".join(fill(c, v) for c, v in zip(cells, r)) + "</w:tr>"
                for r in new_rules)
j = tbl.end() - len("</w:tbl>")
E.doc = E.doc[:j] + added + E.doc[j:]
# คอลัมน์ "ระดับ" แคบจนคำว่า Medium ถูกตัด (มีมาตั้งแต่ตารางเดิม): ย้ายความกว้าง 250 จากคอลัมน์ชื่อกฎ
tbl = re.search(r"<w:tbl>(?:(?!</w:tbl>).)*>MD-0026<.*?</w:tbl>", E.doc, re.S)
t2 = (tbl.group(0).replace('<w:gridCol w:w="3250"/>', '<w:gridCol w:w="3000"/>')
      .replace('<w:gridCol w:w="1000"/>', '<w:gridCol w:w="1250"/>')
      .replace('<w:tcW w:w="3250"', '<w:tcW w:w="3000"').replace('<w:tcW w:w="1000"', '<w:tcW w:w="1250"'))
E.doc = E.doc[:tbl.start()] + t2 + E.doc[tbl.end():]
T.write_doc(E.doc)
