import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dfd import Diagram  # noqa: E402

OUT = "/home/claude/thesis/figs/out"
os.makedirs(OUT, exist_ok=True)
which = sys.argv[1:] or ["ctx", "l1", "l2", "er", "flow", "site"]

# ---------------------------------------------------------------- Context Diagram
if "ctx" in which:
    c = Diagram(860, 640)
    p0 = c.proc(430, 320, 230, 130, "0", "ระบบตรวจจับภัยคุกคาม\nบน macOS")
    es = c.ext(95, 320, 160, 84, "macOS Endpoint\nSecurity\n(eslogger)")
    an = c.ext(765, 320, 170, 84, "ผู้วิเคราะห์\nความปลอดภัย")
    dev = c.ext(430, 60, 220, 56, "ผู้พัฒนากฎตรวจจับ")
    ts = c.ext(430, 582, 200, 56, "ผู้ทดสอบระบบ")
    c.arrow(es["r"], p0["l"])
    c.label(245, 290, "ข้อมูลเหตุการณ์\n(JSON)")
    c.arrow((p0["r"][0], 296), (an["l"][0], 296))
    c.label(612, 250, "การแจ้งเตือน\nหลักฐาน\nเสียงแจ้งเตือน")
    c.arrow((an["l"][0], 346), (p0["r"][0], 346))
    c.label(612, 384, "ผลการตัดสิน\nคำค้นหา")
    c.arrow(dev["b"], p0["t"])
    c.label(440, 172, "กฎตรวจจับ (YAML)", anchor="start")
    c.arrow((390, ts["t"][1]), (390, p0["b"][1]))
    c.label(380, 470, "ช่วงเวลาการทดสอบ\n(runs.csv)", anchor="end")
    c.arrow((470, p0["b"][1]), (470, ts["t"][1]))
    c.label(480, 470, "รายงานผลการวัด", anchor="start")
    c.render(f"{OUT}/ctx.png")

# ---------------------------------------------------------------- DFD Level 1
if "l1" in which:
    c = Diagram(820, 1210)
    L, C, R = 118, 410, 700
    es = c.ext(C, 48, 300, 52, "macOS Endpoint Security (eslogger)")
    p1 = c.proc(C, 168, 250, 86, "1.0", "รับและคัดกรองเหตุการณ์\n(Collector)")
    p2 = c.proc(C, 318, 250, 86, "2.0", "แปลงเป็นรูปแบบกลาง\n(Normalizer)")
    p3 = c.proc(C, 478, 250, 86, "3.0", "ตรวจจับตามกฎ\n(Rule Engine)")
    p4 = c.proc(C, 690, 250, 100, "4.0", "แสดงผลและบันทึก\nการตัดสิน\n(Dashboard)")
    p5 = c.proc(C, 985, 250, 90, "5.0", "ประเมินผลการตรวจจับ\n(report.py)")
    d1 = c.store(R, 318, 170, 44, "D1", "events")
    d2 = c.store(R, 478, 170, 44, "D2", "alerts")
    d3 = c.store(L, 478, 190, 44, "D3", "ไฟล์กฎ (YAML)")
    d4 = c.store(R, 820, 170, 44, "D4", "alert_verdicts")
    dev = c.ext(L, 340, 176, 52, "ผู้พัฒนากฎ")
    an = c.ext(L, 800, 176, 62, "ผู้วิเคราะห์\nความปลอดภัย")
    d1b = c.store(L, 945, 190, 40, "D1", "events", dup=True)
    d2b = c.store(L, 1010, 190, 40, "D2", "alerts", dup=True)
    d5 = c.store(R, 1085, 170, 44, "D5", "runs.csv")
    ts = c.ext(R, 1170, 176, 50, "ผู้ทดสอบระบบ")

    c.arrow(es["b"], p1["t"]); c.label(C + 10, 98, "ข้อมูลเหตุการณ์ (JSON)", anchor="start")
    c.arrow(p1["b"], p2["t"]); c.label(C + 10, 243, "เหตุการณ์ที่ผ่านการคัดกรอง", anchor="start")
    c.arrow(p2["r"], d1["l"]); c.label(575, 300, "เหตุการณ์", size=13)
    c.arrow(p2["b"], p3["t"]); c.label(C + 10, 400, "เหตุการณ์มาตรฐาน + event_id", anchor="start")
    c.arrow(dev["b"], d3["t"]); c.label(L + 8, 418, "เพิ่ม/แก้ไขกฎ", anchor="start", size=13)
    c.arrow(d3["r"], p3["l"]); c.label(250, 462, "กฎ", size=13)
    c.arrow(p3["r"], d2["l"]); c.label(575, 460, "การแจ้งเตือน", size=12)
    # stores -> dashboard
    c.arrow((R, d2["b"][1]), (R, 658), (p4["r"][0], 658)); c.label(604, 646, "การแจ้งเตือน", size=13)
    c.arrow((785, 318), (805, 318), (805, 692), (p4["r"][0], 692)); c.label(604, 680, "เหตุการณ์", size=13)
    c.arrow((L, d3["b"][1]), (L, 600), (330, 600), (330, p4["t"][1])); c.label(225, 588, "ชื่อและคำอธิบายกฎ", size=13)
    c.arrow((480, p4["b"][1]), (480, 820), d4["l"]); c.label(548, 808, "ผลการตัดสิน", size=13)
    c.arrow((R, d4["t"][1]), (R, 722), (p4["r"][0], 722)); c.label(604, 735, "ผลการตัดสินเดิม", size=13)
    # dashboard <-> analyst
    c.arrow((330, p4["b"][1]), (330, 788), (an["r"][0], 788)); c.label(272, 765, "การแจ้งเตือน\nและหลักฐาน", size=13)
    c.arrow((an["r"][0], 815), (370, 815), (370, p4["b"][1])); c.label(285, 838, "ผลการตัดสิน\nคำค้นหา", size=13)
    # evaluation
    c.arrow(d1b["r"], (p5["l"][0], 945)); c.label(250, 933, "เหตุการณ์", size=13)
    c.arrow(d2b["r"], (p5["l"][0], 1010)); c.label(250, 998, "การแจ้งเตือน", size=13)
    c.arrow((R, d4["b"][1]), (R, 960), (p5["r"][0], 960)); c.label(604, 948, "ผลการตัดสิน", size=13)
    c.arrow(d5["l"], (480, 1085), (480, p5["b"][1])); c.label(552, 1073, "ช่วงเวลาทดสอบ", size=13)
    c.arrow(ts["t"], d5["b"]); c.label(R + 10, 1127, "บันทึกช่วงเวลา", anchor="start", size=13)
    c.arrow((370, p5["b"][1]), (370, 1170), ts["l"]); c.label(480, 1158, "รายงานผลการวัด", size=13)
    c.render(f"{OUT}/l1.png")

# ---------------------------------------------------------------- DFD Level 2 (process 3.0)
if "l2" in which:
    c = Diagram(820, 940)
    L, R = 175, 560
    p2 = c.proc(R, 52, 230, 76, "2.0", "Normalizer")
    d3 = c.store(L, 60, 200, 44, "D3", "ไฟล์กฎ (YAML)")
    p31 = c.proc(L, 215, 240, 96, "3.1", "โหลดและตรวจสอบ\nรูปแบบกฎ")
    p32 = c.proc(R, 215, 270, 96, "3.2", "คัดกฎตาม\nชนิดเหตุการณ์")
    p33 = c.proc(R, 385, 270, 96, "3.3", "เทียบเงื่อนไข\nของแต่ละ selection")
    p34 = c.proc(R, 555, 270, 96, "3.4", "ประเมินเงื่อนไขรวม\n(condition)")
    p35 = c.proc(R, 725, 270, 96, "3.5", "สร้างการแจ้งเตือน\nและส่งเสียง")
    d2 = c.store(L, 725, 190, 44, "D2", "alerts")
    an = c.ext(R, 890, 220, 56, "ผู้วิเคราะห์ความปลอดภัย")
    c.arrow(d3["b"], p31["t"]); c.label(L + 10, 122, "ไฟล์กฎ", anchor="start", size=13)
    c.arrow(p31["r"], p32["l"]); c.label(360, 190, "กฎที่พร้อมใช้\n(โหลดครั้งเดียว)", size=13)
    c.arrow(p2["b"], p32["t"]); c.label(R + 10, 128, "เหตุการณ์มาตรฐาน\n+ event_id", anchor="start", size=13)
    c.arrow(p32["b"], p33["t"]); c.label(R + 10, 300, "เหตุการณ์ + กฎที่ตรงชนิด", anchor="start", size=13)
    c.arrow(p33["b"], p34["t"]); c.label(R + 10, 470, "ผลจริง/เท็จของแต่ละ selection", anchor="start", size=13)
    c.arrow(p34["b"], p35["t"]); c.label(R + 10, 640, "กฎที่ตรงเงื่อนไข", anchor="start", size=13)
    c.arrow(p35["l"], d2["r"]); c.label(345, 710, "การแจ้งเตือน", size=13)
    c.arrow(p35["b"], an["t"]); c.label(R + 10, 822, "เสียงแจ้งเตือน และข้อความ ALERT", anchor="start", size=13)
    c.render(f"{OUT}/l2.png")

# ---------------------------------------------------------------- ER Diagram
if "er" in which:
    c = Diagram(900, 520)
    ev, evh = c.entity(20, 40, 270, "events", [
        ("PK", "id", "INTEGER"), ("", "ts_event", "TEXT"), ("", "ts_ingest", "TEXT"), ("", "event_type", "TEXT"),
        ("", "pid", "INTEGER"), ("", "ppid", "INTEGER"), ("", "Image", "TEXT"), ("", "ParentImage", "TEXT"),
        ("", "CommandLine", "TEXT"), ("", "TargetFilename", "TEXT"), ("", "SourceFilename", "TEXT"),
        ("", "SigningId", "TEXT"), ("", "User", "INTEGER")])
    al, alh = c.entity(360, 40, 240, "alerts", [
        ("PK", "id", "INTEGER"), ("FK", "event_id", "INTEGER"), ("FK", "rule_id", "TEXT"), ("", "title", "TEXT"),
        ("", "level", "TEXT"), ("", "tactic", "TEXT"), ("", "technique", "TEXT"), ("", "plain_th", "TEXT"),
        ("", "ts_event", "TEXT"), ("", "ts_alert", "TEXT")])
    vd, vdh = c.entity(660, 40, 220, "alert_verdicts", [
        ("PK,FK", "alert_id", "INTEGER"), ("", "verdict", "TEXT"), ("", "note", "TEXT"), ("", "ts", "TEXT")], kw=54)
    ru, ruh = c.entity(660, 250, 220, "rule (ไฟล์ YAML)", [
        ("PK", "id", "TEXT"), ("", "title", "TEXT"), ("", "level", "TEXT"), ("", "tags", "LIST"),
        ("", "logsource", "MAP"), ("", "detection", "MAP")], dashed=True)
    # events.id 1 --- 0..N alerts.event_id
    y1, y2 = ev["id"], al["event_id"]
    c.line((290, y1), (325, y1), (325, y2), (360, y2))
    c.end_one(290, y1, -1); c.end_many_opt(360, y2, 1)
    # alerts.id 1 --- 0..1 alert_verdicts.alert_id
    y1, y2 = al["id"], vd["alert_id"]
    c.line((600, y1), (630, y1), (630, y2), (660, y2))
    c.end_one(600, y1, -1); c.end_one_opt(660, y2, 1)
    # rule.id 1 --- 0..N alerts.rule_id
    y1, y2 = ru["id"], al["rule_id"]
    c.line((660, y1), (640, y1), (640, y2), (600, y2))
    c.end_one(660, y1, 1); c.end_many_opt(600, y2, -1)
    c.label(780, 225, "เก็บในไฟล์ verdicts.db แยกต่างหาก", size=13)
    c.label(770, 455, "กรอบเส้นประ = ไม่ใช่ตารางในฐานข้อมูล", size=13)
    c.render(f"{OUT}/er.png")

# ---------------------------------------------------------------- Flowchart: rule matching
if "flow" in which:
    c = Diagram(780, 1060)
    X, R, L = 320, 590, 40
    s = c.oval(X, 30, 330, 40, "เริ่ม: ได้รับเหตุการณ์มาตรฐาน 1 รายการ")
    b1 = c.box(X, 100, 220, 44, "หยิบกฎข้อถัดไป")
    d1 = c.diamond(X, 205, 260, 110, "ชนิดเหตุการณ์ตรงกับ\nlogsource ของกฎ?")
    b2 = c.box(X, 335, 400, 76, "เทียบแต่ละ selection: ทุกฟิลด์ต้องตรงกัน (AND)\nค่าในรายการตรงอย่างน้อยหนึ่งค่า (OR)\nเทียบตาม modifier โดยไม่สนตัวพิมพ์")
    b3 = c.box(X, 440, 360, 56, "ประเมิน condition ของกฎ\n(and, or, not, 1 of, all of)")
    d2 = c.diamond(X, 550, 200, 96, "ผลเป็นจริง?")
    b4 = c.box(R, 550, 230, 76, "บันทึกการแจ้งเตือน\nลงตาราง alerts\nพิมพ์ ALERT ลง Terminal")
    d3 = c.diamond(X, 690, 200, 96, "ครบทุกกฎ?")
    d4 = c.diamond(X, 820, 230, 100, "มีการแจ้งเตือน\nจากเหตุการณ์นี้?")
    b5 = c.box(X, 935, 400, 56, "เล่นเสียงตามระดับรุนแรงสูงสุด\n(เว้นห่างจากครั้งก่อนอย่างน้อย 2 วินาที)")
    e = c.oval(X, 1025, 300, 40, "สิ้นสุด: รอเหตุการณ์ถัดไป")
    c.arrow(s["b"], b1["t"]); c.arrow(b1["b"], d1["t"])
    c.arrow(d1["b"], b2["t"]); c.label(X + 10, 272, "ใช่", anchor="start")
    c.arrow(b2["b"], b3["t"]); c.arrow(b3["b"], d2["t"])
    c.arrow(d2["r"], b4["l"]); c.label(440, 538, "ใช่")
    c.arrow(b4["b"], (R, 690), d3["r"])
    c.arrow(d2["b"], d3["t"]); c.label(X + 10, 615, "ไม่ใช่", anchor="start")
    c.line(d1["r"], (745, 205), (745, 690), (R, 690)); c.dot(R, 690)
    c.label(495, 192, "ไม่ใช่")
    c.arrow(d3["l"], (L, 690), (L, 100), b1["l"]); c.label(160, 677, "ไม่ใช่")
    c.arrow(d3["b"], d4["t"]); c.label(X + 10, 752, "ใช่", anchor="start")
    c.arrow(d4["b"], b5["t"]); c.label(X + 10, 885, "ใช่", anchor="start")
    c.arrow(b5["b"], e["t"])
    c.arrow(d4["r"], (R + 40, 820), (R + 40, 1025), e["r"]); c.label(500, 808, "ไม่ใช่")
    c.render(f"{OUT}/flow.png")

# ---------------------------------------------------------------- Site map
if "site" in which:
    c = Diagram(900, 420)
    root = c.box(450, 40, 300, 48, "macOS Detect Dashboard")
    xs = [115, 340, 565, 790]
    names = ["Overview\n(ภาพรวม)", "Alerts\n(การแจ้งเตือน)", "Event search\n(ค้นหาเหตุการณ์)", "Rules & ATT&CK\n(กฎและความครอบคลุม)"]
    pages = [c.box(x, 150, 200, 58, n) for x, n in zip(xs, names)]
    c.line(root["b"], (450, 92))
    c.line((xs[0], 92), (xs[-1], 92))
    for p, x in zip(pages, xs):
        c.arrow((x, 92), p["t"])
    subs = {
        0: ["แถบสรุปตัวเลข", "แถบการแจ้งเตือนตามเวลา\n(15m / 1h / 6h / 24h)", "การแจ้งเตือนล่าสุด", "ขั้นตอนการโจมตี"],
        1: ["ค้นหาและกรองตาม\nความรุนแรง / สถานะ", "รายละเอียดการแจ้งเตือน\n(process tree, หลักฐาน)", "ตัดสิน True / False\npositive"],
        2: ["ค้นหาโปรแกรม\nคำสั่ง หรือไฟล์", "กรองชนิดเหตุการณ์", "Refresh"],
        3: ["ตาราง ATT&CK\ncoverage", "ตารางกฎทั้งหมด\nพร้อมจำนวนครั้ง"],
    }
    for i, items in subs.items():
        x = xs[i]
        y = 205
        top = pages[i]["b"][1]
        ys = []
        for t in items:
            h = 48 if "\n" in t else 34
            c.items.append(f'<rect x="{x - 76}" y="{y}" width="180" height="{h}" class="s"/>')
            c._text(x + 14, y + h / 2, t, size=14)
            ys.append(y + h / 2)
            y += h + 12
        c.line((x - 92, top), (x - 92, ys[-1]))
        for yy in ys:
            c.line((x - 92, yy), (x - 76, yy))
    c.render(f"{OUT}/site.png")
print("done", which)
