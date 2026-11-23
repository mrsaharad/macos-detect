"""
Incident grouping (v2) — รวม alert ที่มาจากต้นตอเดียวกันเป็น 1 เหตุการณ์ ลดภาระผู้วิเคราะห์ (alert fatigue)
แนวคิดเดียวกับ Storyline ของ EDR เชิงพาณิชย์ แต่แบบง่ายและอธิบายได้:

  ต้นตอ (root) ของ alert = ไล่โปรเซสแม่ขึ้นไปในตาราง events จนถึงโปรเซสที่แม่เป็น launchd (pid 1)
                           หรือหาแม่ต่อไม่ได้ เช่น Terminal.app, CleanMyMac, pwsh ที่เริ่มก่อน collector
  incident               = alert ที่มีต้นตอเดียวกัน และห่างจาก alert ก่อนหน้าของต้นตอนั้นไม่เกิน GAP นาที

ใช้ทั้งใน dashboard/app.py (มุมมอง Incidents) และ scripts/report.py (alert ต่อ incident)
"""
from datetime import timedelta

GAP = timedelta(minutes=30)
MAX_DEPTH = 12


def find_root(db, pid, ppid, image, event_id, cache=None):
    """คืน (root_pid, root_image): โปรเซสชั้นที่อยู่ "ใต้" แอปบนสุด (ลูกของโปรเซสที่ launchd เปิด)
    เช่น แท็บ shell ใน Terminal/แอปอื่น หรือสคริปต์ที่รันโดยแอป — แอปบนสุดอย่าง Terminal รันหลายงานพร้อมกัน
    จึงไม่ใช้เป็นต้นตอ ถ้าหาแม่ต่อไม่ได้ (เริ่มก่อน collector) ใช้โปรเซสสุดท้ายที่รู้จัก"""
    cache = {} if cache is None else cache
    chain = [(pid, image)]
    cur, ev, reached_launchd = ppid, event_id, False
    for _ in range(MAX_DEPTH):
        if cur in (None, 0):
            break
        if cur == 1:
            reached_launchd = True
            break
        key = (cur, ev // 5000)                    # pid ถูกใช้ซ้ำได้ จึงผูกกับช่วงของ event id ด้วย
        if key not in cache:
            cache[key] = db.execute(
                "SELECT ppid, Image FROM events WHERE pid=? AND id<=? AND event_type IN ('exec','fork') "
                "ORDER BY id DESC LIMIT 1", (int(cur), int(ev))).fetchone()
        row = cache[key]
        if not row:
            chain.append((cur, None))
            break
        chain.append((cur, row[1]))
        cur = row[0]
    if reached_launchd and len(chain) >= 2:
        return chain[-2]                           # ใต้แอปบนสุดหนึ่งชั้น
    return chain[-1]


def group(db, alerts):
    """alerts: list ของ dict ที่มี id, event_id, pid, ppid, Image, ParentImage, t (datetime)
    คืน dict alert_id -> incident key (str) และ dict incident key -> ข้อมูลสรุป"""
    cache, last, assign, info = {}, {}, {}, {}
    for a in sorted(alerts, key=lambda x: x["t"]):
        rpid, rimg = find_root(db, a["pid"], a["ppid"], a["Image"], a["event_id"], cache)
        if rimg is None and rpid == a["ppid"]:
            rimg = a.get("ParentImage")
        root = (rpid, rimg or "(started before monitoring)")
        prev = last.get(root)
        if prev and a["t"] - prev[1] <= GAP:
            inc = prev[0]
        else:
            inc = f"INC-{a['id']}"
            info[inc] = {"root_pid": rpid, "root_image": root[1], "first": a["t"], "alerts": []}
        last[root] = (inc, a["t"])
        assign[a["id"]] = inc
        info[inc]["alerts"].append(a["id"])
        info[inc]["last"] = a["t"]
    return assign, info
