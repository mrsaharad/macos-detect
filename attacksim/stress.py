"""
Stress test และ A/B overhead ของระบบตรวจจับ

stress  (ต้องเปิด collector): สร้างโปรเซสสั้นๆ (/usr/bin/true พร้อมรหัสประจำตัว) ตามอัตราที่กำหนด
        แล้วนับว่า collector เก็บ exec event ได้ครบกี่ตัว (event หล่น) และช้ากว่าเวลาจริงเท่าไหร่ (ingest lag)
        อัตรา: 50, 200, 1000 โปรเซส/วินาที และเร็วที่สุดที่ทำได้ — ครั้งละ 15 วินาที
ab      : จับเวลางานมาตรฐานเดียวกัน (รัน 3,000 โปรเซส + สร้าง/ลบ 3,000 ไฟล์) ซ้ำ 5 รอบ
        รันครั้งหนึ่งตอนเปิด collector (--state on) และอีกครั้งตอนปิด (--state off) แล้ว report.py เทียบกัน

ผล: data/results/stress.csv, data/results/ab.csv ; ช่วงเวลาที่รันบันทึกใน data/stress_runs.csv (report.py ตัดออกจากการรันกฎย้อนหลัง)
รัน:  .venv/bin/python attacksim/stress.py stress --version v1
      .venv/bin/python attacksim/stress.py ab --state on  --version v1
      (ปิด collector) .venv/bin/python attacksim/stress.py ab --state off --version v1
"""
import argparse
import csv
import os
import shutil
import sqlite3
import statistics
import subprocess
import time
import uuid
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "detect.db")
RES = os.path.join(ROOT, "data", "results")
RUNS = os.path.join(ROOT, "data", "stress_runs.csv")
W = os.path.expanduser("~/Library/Caches/macdetect-stress")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse(s):
    s = s.replace("Z", "+00:00")
    head, rest = s.split(".", 1)
    return datetime.fromisoformat(f"{head}.{rest[:6]}{rest[-6:]}")


def append(path, row):
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new:
            w.writeheader()
        w.writerow(row)


def spawn(n, rate, tag):
    """รัน /usr/bin/true n ครั้งที่อัตรา rate ต่อวินาที (0 = เร็วที่สุด) คืนเวลาที่ใช้จริง"""
    t0 = time.monotonic()
    procs = []
    for i in range(n):
        procs.append(subprocess.Popen(["/usr/bin/true", f"{tag}-{i}"]))
        if len(procs) >= 64:                    # เก็บ zombie เป็นระยะ
            for p in procs:
                p.wait()
            procs.clear()
        if rate:
            ahead = (i + 1) / rate - (time.monotonic() - t0)
            if ahead > 0:
                time.sleep(ahead)
    for p in procs:
        p.wait()
    return time.monotonic() - t0


def captured(tag):
    with sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=30) as db:
        return db.execute("SELECT COUNT(*), MAX(julianday(ts_ingest) - julianday(ts_event)) * 86400000 "
                          "FROM events WHERE event_type='exec' AND CommandLine LIKE ?", (f"%{tag}-%",)).fetchone()


def stress(args):
    for rate in (50, 200, 1000, 0):
        n = int(rate * 15) if rate else 15000
        tag = f"macdetect-stress-{uuid.uuid4().hex[:8]}"
        start = now()
        took = spawn(n, rate, tag)
        # รอ collector ตามทัน: นับซ้ำจนจำนวนไม่เพิ่มอีก 10 วินาที
        last, stable_since, t_wait = -1, time.monotonic(), time.monotonic()
        while time.monotonic() - stable_since < 10 and time.monotonic() - t_wait < 300:
            c, lag = captured(tag)
            if c != last:
                last, stable_since = c, time.monotonic()
            time.sleep(1)
        catch_up = time.monotonic() - t_wait - 10
        c, lag = captured(tag)
        end = now()
        row = {"version": args.version, "target_rate": rate or "max", "spawned": n,
               "actual_rate": round(n / took, 1), "captured": c, "lost": n - c,
               "loss_pct": round((n - c) / n * 100, 3), "max_lag_ms": round(lag or 0, 1),
               "catch_up_s": round(max(0.0, catch_up), 1), "start_utc": start, "end_utc": end}
        append(os.path.join(RES, "stress.csv"), row)
        append(RUNS, {"id": f"stress-{rate or 'max'}", "version": args.version, "start_utc": start, "end_utc": end})
        print(f"อัตรา {row['target_rate']:>4}/s (จริง {row['actual_rate']}/s): เก็บได้ {c}/{n} "
              f"หล่น {row['loss_pct']}%  lag สูงสุด {row['max_lag_ms']} ms  ตามทันใน {row['catch_up_s']} s")
        time.sleep(5)


def workload():
    t0 = time.monotonic()
    spawn(3000, 0, "macdetect-ab")
    os.makedirs(W, exist_ok=True)
    for i in range(3000):
        f = os.path.join(W, f"f{i}")
        open(f, "w").close()
        os.remove(f)
    return time.monotonic() - t0


def ab(args):
    start = now()
    times = []
    for i in range(5):
        times.append(workload())
        print(f"  รอบ {i + 1}: {times[-1]:.2f} s")
        time.sleep(3)
    shutil.rmtree(W, ignore_errors=True)
    end = now()
    row = {"version": args.version, "state": args.state, "runs": len(times),
           "mean_s": round(statistics.mean(times), 3), "sd_s": round(statistics.stdev(times), 3),
           "min_s": round(min(times), 3), "max_s": round(max(times), 3), "start_utc": start, "end_utc": end}
    append(os.path.join(RES, "ab.csv"), row)
    append(RUNS, {"id": f"ab-{args.state}", "version": args.version, "start_utc": start, "end_utc": end})
    print(f"collector {args.state}: เฉลี่ย {row['mean_s']} s (SD {row['sd_s']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["stress", "ab"])
    ap.add_argument("--version", required=True)
    ap.add_argument("--state", choices=["on", "off"], help="สำหรับ ab: collector เปิดหรือปิดอยู่")
    args = ap.parse_args()
    os.makedirs(RES, exist_ok=True)
    if args.mode == "stress":
        stress(args)
    else:
        if not args.state:
            ap.error("ab ต้องระบุ --state on หรือ off")
        ab(args)


if __name__ == "__main__":
    main()
