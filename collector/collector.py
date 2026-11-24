"""
Collector — ตัวหลักของระบบ (รปภ. หน้าสายพาน)

สายพาน: eslogger --(JSON ทีละบรรทัด)--> collector.py
ทุกบรรทัด:  ตรวจว่าเป็น JSON -> normalize -> เก็บลง events -> เทียบกฎ -> เก็บ alerts

วิธีรัน:
    สด (v2):   sudo eslogger exec fork exit create rename unlink close truncate setflags setextattr deleteextattr \
                   btm_launch_item_add | python collector/collector.py
    สด (v1):   sudo eslogger exec fork exit create rename unlink | python collector/collector.py
    จากไฟล์:   python collector/collector.py --file data/sample.jsonl
ตัวเลือก:   --db data/detect.db   --rules rules   --quiet
หยุด:       Ctrl+C (ข้อมูลที่รับแล้วถูกบันทึกก่อนออก)
"""
import argparse
import json
import os
import re
import shutil
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

# ให้ import โฟลเดอร์ engine/ และ collector/ ได้ ไม่ว่าจะรันจากที่ไหน
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "collector"))

from normalize import Normalizer          # noqa: E402
import store                              # noqa: E402
from engine.rules import load_rules       # noqa: E402

# ---------------- เสียงกริ่งเมื่อมี alert ----------------
# ใช้ afplay (มากับ macOS) — ห้ามใช้ osascript เพราะกฎ MD-0006 จะจับแล้วเกิด alert วนไม่รู้จบ
SOUNDS = {"critical": "/System/Library/Sounds/Sosumi.aiff", "high": "/System/Library/Sounds/Sosumi.aiff",
          "medium": "/System/Library/Sounds/Glass.aiff", "low": "/System/Library/Sounds/Glass.aiff"}
AFPLAY = shutil.which("afplay")
_last_ring = 0.0


def ring(level):
    """เล่นเสียงแบบไม่รอ (ไม่ทำให้ collector ช้า) และเว้นอย่างน้อย 2 วินาที กันเสียงรัวตอน alert มาเป็นชุด"""
    global _last_ring
    sound = SOUNDS.get(level)
    if not AFPLAY or not sound or not os.path.exists(sound) or time.monotonic() - _last_ring < 2:
        return
    _last_ring = time.monotonic()
    subprocess.Popen([AFPLAY, sound], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


SEQ = re.compile(r'"global_seq_num":(\d+)')
# close ที่ไม่ได้แก้ไฟล์มีเยอะมาก ตัดทิ้งตั้งแต่ยังเป็นข้อความ ไม่ต้องแปลง JSON (ประหยัด CPU)
CLOSE_UNMODIFIED = re.compile(r'"close":\{"modified":false')
HEALTH_EVERY = 60          # วินาที — บันทึก heartbeat ลงตาราง health
# v2: event ที่ subscribe (ใช้กับ --spawn และ start_collector.command)
ES_EVENTS = ["exec", "fork", "exit", "create", "rename", "unlink", "close", "truncate", "setflags", "setextattr",
             "deleteextattr", "btm_launch_item_add"]
# --spawn แยก eslogger เป็น 2 โปรเซส: close มีมาก (~40 ครั้งต่อโปรเซส) จน eslogger ตัวเดียวใช้ CPU เต็มคอร์
# ตอนโหลดสูง แล้ว exec ต้องรอคิวหลัง close นานหลายนาที (stress v2) แยกแล้ว event ที่กฎใช้ไม่ต้องรอ close
ES_MAIN = [e for e in ES_EVENTS if e != "close"]
ES_CLOSE = ["close"]


class Window:
    """ตัวนับของ heartbeat (thread-safe เพราะ --spawn อ่าน eslogger 2 ตัวจาก 2 thread)"""
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.c = {"events": 0, "stored": 0, "dropped": 0, "pruned": 0}

    def add(self, key, n=1):
        with self.lock:
            self.c[key] += n

    def take(self):
        with self.lock:
            c, self.c = self.c, {"events": 0, "stored": 0, "dropped": 0, "pruned": 0}
        return c


def prefilter(line, last, win):
    """คัดบรรทัดแบบถูกๆ ก่อนแปลง JSON: นับ event, ตรวจเลขลำดับที่ขาด (ต่อ eslogger หนึ่งตัว), ทิ้ง close ที่ไม่ได้แก้ไฟล์
    last = [global_seq_num ล่าสุดของ stream นี้]  คืนบรรทัด หรือ None ถ้าทิ้ง"""
    line = line.strip()
    if not line.startswith("{"):          # ยามหน้าประตู: ไม่ใช่ JSON ข้าม
        return None
    m = SEQ.search(line)
    if m:
        seq = int(m.group(1))
        if last[0] is not None and seq > last[0] + 1:
            win.add("dropped", seq - last[0] - 1)
        last[0] = seq
    win.add("events")
    if CLOSE_UNMODIFIED.search(line):
        return None
    return line


def spawn_streams(win):
    """เปิด eslogger 2 ตัว แต่ละตัวมี thread อ่านแล้วคัดบรรทัด ส่งเข้าคิวเดียวที่ให้ event หลักมาก่อน close
    คืน (generator ของบรรทัด, รายการโปรเซส) — eslogger ตัวใดจบ generator จบ (launchd จะเปิด collector ใหม่)"""
    q = queue.PriorityQueue(maxsize=200000)
    n = [0]
    nlock = threading.Lock()
    procs = []

    def reader(proc, prio):
        last = [None]
        for raw in proc.stdout:
            line = prefilter(raw, last, win)
            if line is not None:
                with nlock:
                    n[0] += 1
                    k = n[0]
                q.put((prio, k, line))
        q.put((2, 0, None))               # eslogger ตัวนี้จบ (ลำดับท้ายสุด: ประมวลผลบรรทัดที่ค้างในคิวก่อน)

    for prio, events in ((0, ES_MAIN), (1, ES_CLOSE)):
        p = subprocess.Popen(["/usr/bin/eslogger"] + events, stdout=subprocess.PIPE, text=True, bufsize=1)
        procs.append(p)
        threading.Thread(target=reader, args=(p, prio), daemon=True).start()

    def gen():
        while True:
            _, _, line = q.get()
            if line is None:
                print("[collector] eslogger หยุดทำงาน ออกเพื่อให้ launchd เปิดใหม่", file=sys.stderr)
                return
            yield line
    return gen(), procs


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def main():
    ap = argparse.ArgumentParser(description="macOS threat detection collector")
    ap.add_argument("--file", help="อ่านจากไฟล์แทน stdin")
    ap.add_argument("--db", default=os.path.join(ROOT, "data", "detect.db"))
    ap.add_argument("--rules", default=os.path.join(ROOT, "rules"))
    ap.add_argument("--quiet", action="store_true", help="ไม่พิมพ์ alert ลงจอ")
    ap.add_argument("--no-sound", action="store_true", help="ไม่เล่นเสียงกริ่งเมื่อมี alert")
    ap.add_argument("--spawn", action="store_true",
                    help="เปิด eslogger เอง (ใช้ตอนรันเป็น LaunchDaemon ด้วยสิทธิ์ root ไม่ต้องต่อท่อจาก shell)")
    ap.add_argument("--retention-days", type=float, default=0,
                    help="ลบ event ที่เก่ากว่า N วัน (ยกเว้นหลักฐานของ alert) ทุกชั่วโมง; 0 = ไม่ลบ "
                         "(ค่าเริ่มต้น เพราะช่วงทดลองต้องเก็บ event ไว้รันกฎย้อนหลัง)")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    db = store.connect(args.db)
    norm = Normalizer()
    win = Window()
    es_procs = []
    if args.spawn:
        lines, es_procs = spawn_streams(win)
    else:
        src = open(args.file, encoding="utf-8") if args.file else sys.stdin
        last = [None]
        lines = (x for x in (prefilter(raw, last, win) for raw in src) if x is not None)
    print(f"[collector] โหลดกฎ {len(rules)} ข้อ  เก็บที่ {args.db}"
          + ("  (eslogger 2 ตัว: หลัก + close)" if args.spawn else ""), file=sys.stderr)

    n_events = n_alerts = 0
    next_prune = 0.0
    next_health = time.monotonic() + HEALTH_EVERY
    store.insert_health(db, now_utc(), 0, 0, 0, 0)          # จุดเริ่มทำงาน
    try:
        for line in lines:
            if time.monotonic() >= next_health and not args.file:
                c = win.take()
                store.insert_health(db, now_utc(), c["events"], c["stored"], c["dropped"], c["pruned"])
                if c["dropped"]:
                    print(f"[collector] ⚠️ event หล่น {c['dropped']} รายการในนาทีที่ผ่านมา", file=sys.stderr)
                next_health = time.monotonic() + HEALTH_EVERY
            try:
                e = json.loads(line)
            except json.JSONDecodeError:           # บรรทัดเสีย (เช่นถูกตัดกลางทาง) ข้าม ไม่ล้ม
                continue
            rec = norm.normalize(e)
            if rec is None:
                continue
            if args.retention_days and time.monotonic() >= next_prune:
                removed = store.prune(db, args.retention_days)
                win.add("pruned", removed)
                print(f"[collector] retention: ลบ event เก่ากว่า {args.retention_days:g} วัน {removed} รายการ",
                      file=sys.stderr)
                next_prune = time.monotonic() + 3600
            rec["ts_ingest"] = now_utc()
            event_id = store.insert_event(db, rec)
            n_events += 1
            win.add("stored")

            hits = []
            for rule in rules:
                if rule.matches(rec):
                    hits.append(rule)
                    store.insert_alert(db, event_id, rule, rec, now_utc())
                    n_alerts += 1
                    if not args.quiet:
                        print(f"ALERT [{rule.level.upper()}] {rule.id} {rule.title}\n"
                              f"    {rec.get('Image')}  {rec.get('CommandLine') or rec.get('TargetFilename') or ''}",
                              flush=True)
            # อ่านไฟล์ย้อนหลัง (--file) ไม่ต้องมีเสียง; รันสดเท่านั้นที่ดัง
            if hits and not args.no_sound and not args.file:
                worst = min(hits, key=lambda r: ["critical", "high", "medium", "low"].index(r.level)
                            if r.level in ("critical", "high", "medium", "low") else 9)
                ring(worst.level)
    except KeyboardInterrupt:
        pass
    finally:
        for p in es_procs:
            p.terminate()
        db.close()
        print(f"\n[collector] จบ: event {n_events}  alert {n_alerts}", file=sys.stderr)


if __name__ == "__main__":
    main()
