"""
Collector — ตัวหลักของระบบ (รปภ. หน้าสายพาน)

สายพาน: eslogger --(JSON ทีละบรรทัด)--> collector.py
ทุกบรรทัด:  ตรวจว่าเป็น JSON -> normalize -> เก็บลง events -> เทียบกฎ -> เก็บ alerts

วิธีรัน:
    สด:        sudo eslogger exec fork exit create rename unlink | python collector/collector.py
    จากไฟล์:   python collector/collector.py --file data/sample.jsonl
ตัวเลือก:   --db data/detect.db   --rules rules   --quiet
หยุด:       Ctrl+C (ข้อมูลที่รับแล้วถูกบันทึกก่อนออก)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
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


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def main():
    ap = argparse.ArgumentParser(description="macOS threat detection collector")
    ap.add_argument("--file", help="อ่านจากไฟล์แทน stdin")
    ap.add_argument("--db", default=os.path.join(ROOT, "data", "detect.db"))
    ap.add_argument("--rules", default=os.path.join(ROOT, "rules"))
    ap.add_argument("--quiet", action="store_true", help="ไม่พิมพ์ alert ลงจอ")
    ap.add_argument("--no-sound", action="store_true", help="ไม่เล่นเสียงกริ่งเมื่อมี alert")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    db = store.connect(args.db)
    norm = Normalizer()
    src = open(args.file, encoding="utf-8") if args.file else sys.stdin
    print(f"[collector] โหลดกฎ {len(rules)} ข้อ  เก็บที่ {args.db}", file=sys.stderr)

    n_events = n_alerts = 0
    try:
        for line in src:
            line = line.strip()
            if not line.startswith("{"):          # ยามหน้าประตู: ไม่ใช่ JSON ข้าม
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:           # บรรทัดเสีย (เช่นถูกตัดกลางทาง) ข้าม ไม่ล้ม
                continue
            rec = norm.normalize(e)
            if rec is None:
                continue
            rec["ts_ingest"] = now_utc()
            event_id = store.insert_event(db, rec)
            n_events += 1

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
        db.close()
        print(f"\n[collector] จบ: event {n_events}  alert {n_alerts}", file=sys.stderr)


if __name__ == "__main__":
    main()
