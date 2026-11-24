"""
วัด System Overhead ของระบบตรวจจับ (วัตถุประสงค์ข้อ 3) — CPU และหน่วยความจำของ collector กับ eslogger

วิธีวัด
  - ทุก --interval วินาที อ่านค่าจาก ps (ไม่ต้องใช้ sudo): เวลา CPU สะสม และ RSS (หน่วยความจำจริงที่ใช้)
  - CPU% = (เวลา CPU ที่เพิ่มขึ้น / เวลาจริงที่ผ่านไป) x 100  → 100% = ใช้ CPU เต็ม 1 คอร์
    (แม่นกว่า %cpu ของ ps ซึ่งเป็นค่าเฉลี่ยแบบหน่วงเวลา)
  - นับ event ที่ collector เก็บได้ในช่วงเดียวกัน และขนาดไฟล์ฐานข้อมูลที่โตขึ้น
ผลลัพธ์
  data/results/overhead.csv           ค่าทุกครั้งที่วัด
  data/results/overhead_summary.json  สรุป (เฉลี่ย / median / P95 / สูงสุด)

รัน:  python scripts/measure_overhead.py --minutes 60      (หยุดก่อนได้ด้วย Ctrl+C ผลที่วัดแล้วยังถูกสรุป)
ปกติ attacksim/baseline.sh จะเรียกสคริปต์นี้ให้เองระหว่างช่วง baseline
"""
import argparse
import csv
import json
import os
import signal
import sqlite3
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.environ.get("DETECT_DB", os.path.join(ROOT, "data", "detect.db"))   # v2 daemon: /Library/Application Support/macdetect/data/detect.db
OUT = os.path.join(ROOT, "data", "results")


def ps_table():
    """pid -> (ppid, เวลา CPU สะสม (วินาที), RSS (KB), คำสั่ง) ของทุกโปรเซส"""
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,time=,rss=,command="],
                         capture_output=True, text=True, check=True).stdout
    table = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, ppid, cpu, rss, cmd = parts
        table[int(pid)] = (int(ppid), cpu_seconds(cpu), int(rss), cmd)
    return table


def cpu_seconds(text):
    """แปลงรูปแบบเวลา CPU ของ ps ([[dd-]hh:]mm:ss.ss) เป็นวินาที"""
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    secs = 0.0
    for part in text.split(":"):
        secs = secs * 60 + float(part)
    return days * 86400 + secs


def find_targets(table):
    """หา collector ที่ทำงานสด และ eslogger ทุกตัวที่ป้อนข้อมูลให้มัน
    v2.1 (--spawn): eslogger 2 ตัวเป็นลูกของ collector  |  v1 (ต่อท่อ): eslogger อยู่ใต้ shell เดียวกับ collector"""
    eslogger = [p for p, (_, _, _, c) in table.items() if c.split()[0].endswith("eslogger")]
    collectors = [p for p, (_, _, _, c) in table.items()
                  if "collector/collector.py" in c and "--file" not in c]
    if not eslogger or not collectors:
        return None
    for col in collectors:
        kids = [e for e in eslogger if table[e][0] == col]
        if kids:
            return {"collector": col, "eslogger": kids}
    es = eslogger[0]
    ancestors, p = set(), es
    while p in table and p > 1:                 # ไล่ขึ้นไปหา shell ที่เป็นแม่ของทั้งคู่
        ancestors.add(table[p][0])
        p = table[p][0]
    paired = [c for c in collectors if table[c][0] in ancestors]
    return {"collector": (paired or collectors)[0], "eslogger": [es]}


def usage(table, pids):
    """(เวลา CPU รวม, RSS รวม KB) ของรายการ pid"""
    return sum(table[p][1] for p in pids), sum(table[p][2] for p in pids)


def event_count():
    try:
        with sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10) as db:
            return db.execute("SELECT MAX(id) FROM events").fetchone()[0] or 0
    except sqlite3.Error:
        return None


def db_bytes():
    return sum(os.path.getsize(DB + s) for s in ("", "-wal", "-shm") if os.path.exists(DB + s))


def pct(values, p):
    v = sorted(values)
    return v[max(0, min(len(v) - 1, round(p / 100 * (len(v) - 1))))]


def stats(values):
    if not values:
        return {}
    return {"mean": round(statistics.mean(values), 2), "median": round(statistics.median(values), 2),
            "p95": round(pct(values, 95), 2), "max": round(max(values), 2)}


def _stop(*_):
    raise KeyboardInterrupt


def main():
    # baseline.sh รันสคริปต์นี้เบื้องหลัง ซึ่ง zsh ตั้งให้ไม่สนใจ Ctrl+C จึงรับ SIGTERM เป็นสัญญาณหยุดด้วย
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    ap = argparse.ArgumentParser(description="วัด CPU/RAM ของ collector + eslogger")
    ap.add_argument("--minutes", type=float, default=60)
    ap.add_argument("--interval", type=float, default=5, help="วัดทุกกี่วินาที")
    ap.add_argument("--tag", default="overhead",
                    help="ชื่อไฟล์ผล เช่น stability → stability.csv / stability_summary.json")
    args = ap.parse_args()

    targets = find_targets(ps_table())
    if not targets:
        sys.exit("ไม่พบ eslogger/collector ที่กำลังทำงาน — เปิด start_collector.command ก่อน")
    print(f"[overhead] วัด collector pid {targets['collector']} และ eslogger pid {targets['eslogger']} "
          f"ทุก {args.interval:g} วินาที นาน {args.minutes:g} นาที (Ctrl+C เพื่อหยุดก่อน)", file=sys.stderr)

    os.makedirs(OUT, exist_ok=True)
    rows, prev, stopped = [], None, None
    start_wall, start_events, start_db = time.monotonic(), event_count(), db_bytes()
    start_utc = datetime.now(timezone.utc)
    try:
        while time.monotonic() - start_wall < args.minutes * 60:
            table, now = ps_table(), time.monotonic()
            if targets["collector"] not in table or any(p not in table for p in targets["eslogger"]):
                stopped = datetime.now(timezone.utc).isoformat(timespec="seconds")
                print(f"[overhead] collector หรือ eslogger หยุดทำงานเมื่อ {stopped} — จบการวัด", file=sys.stderr)
                break
            cur = {"collector": usage(table, [targets["collector"]]), "eslogger": usage(table, targets["eslogger"])}
            if prev:
                dt = now - prev[0]
                row = {"ts_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                for k in targets:
                    row[f"{k}_cpu_pct"] = round((cur[k][0] - prev[1][k][0]) / dt * 100, 2)
                    row[f"{k}_rss_mb"] = round(cur[k][1] / 1024, 1)
                row["total_cpu_pct"] = round(row["collector_cpu_pct"] + row["eslogger_cpu_pct"], 2)
                row["total_rss_mb"] = round(row["collector_rss_mb"] + row["eslogger_rss_mb"], 1)
                rows.append(row)
            prev = (now, cur)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    signal.signal(signal.SIGINT, signal.SIG_IGN)     # กำลังบันทึกผล ห้ามถูกขัดจังหวะ
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    if not rows:
        sys.exit("ยังไม่มีข้อมูล (ต้องวัดอย่างน้อย 2 ครั้ง)")
    with open(os.path.join(OUT, f"{args.tag}.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    minutes = (time.monotonic() - start_wall) / 60
    end_events = event_count()
    summary = {
        "start_utc": start_utc.isoformat(timespec="seconds"),
        "minutes": round(minutes, 1), "samples": len(rows), "interval_s": args.interval,
        "cpu_pct": {k: stats([r[f"{k}_cpu_pct"] for r in rows]) for k in ("collector", "eslogger", "total")},
        "rss_mb": {k: stats([r[f"{k}_rss_mb"] for r in rows]) for k in ("collector", "eslogger", "total")},
        "events": (end_events - start_events) if None not in (start_events, end_events) else None,
        "db_growth_mb": round((db_bytes() - start_db) / 1048576, 2),
        "note": "CPU% คิดต่อ 1 คอร์ (100% = เต็ม 1 คอร์)",
        "planned_minutes": args.minutes,
        "sensor_stopped_at": stopped,      # None = collector/eslogger ทำงานตลอดช่วงที่วัด
        "pids": targets,
    }
    if summary["events"] is not None and minutes:
        summary["events_per_sec"] = round(summary["events"] / (minutes * 60), 1)
    with open(os.path.join(OUT, f"{args.tag}_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    c, r = summary["cpu_pct"]["total"], summary["rss_mb"]["total"]
    print(f"\n=== System Overhead ({summary['minutes']} นาที, {len(rows)} ครั้ง) ===")
    print(f"  CPU รวม (collector+eslogger): เฉลี่ย {c['mean']}%  P95 {c['p95']}%  สูงสุด {c['max']}%  (ต่อ 1 คอร์)")
    print(f"  RAM รวม: เฉลี่ย {r['mean']} MB  สูงสุด {r['max']} MB")
    print(f"  event {summary['events']:,} รายการ ({summary.get('events_per_sec')}/วินาที)  ฐานข้อมูลโต {summary['db_growth_mb']} MB")
    if stopped:
        print(f"  ⚠️ collector/eslogger หยุดทำงานเมื่อ {stopped} (ก่อนครบเวลาที่กำหนด)")
    print(f"บันทึกไว้ที่ {OUT}/{args.tag}.csv และ {args.tag}_summary.json")


if __name__ == "__main__":
    main()
