"""
คำนวณผลสำหรับบทที่ 4 จาก data/detect.db + data/runs.csv

runs.csv = ช่วงเวลาที่รันแต่ละ technique (ground truth) และช่วง BASELINE (ใช้เครื่องปกติ)
ผลที่ได้:
  - ตาราง per technique: จำนวน event ในช่วงนั้น, alert ที่ตรง technique, สถานะ
      Detected               = มี alert ของ technique นั้นในช่วงเวลา
      Visible-Not-Detected?  = มี event ในช่วงเวลา แต่ไม่มี alert ที่ตรง  (ต้องตรวจด้วยตาว่า event ของการโจมตีอยู่จริงไหม)
      Not-Visible?           = แทบไม่มี event ในช่วงเวลา (ต้องตรวจด้วยตา + ดูว่า test สำเร็จไหม)
  - Detection Rate แยก dev / eval
  - Latency (median / P95 / max) ของ alert ที่ตรง technique
  - False Positive ต่อชั่วโมงในช่วง BASELINE
  - Precision (alert ที่ตรง technique ใน window / alert ทั้งหมดใน window+baseline)
บันทึกผลเป็น CSV ใน data/results/ เพื่อนำไปทำตาราง/กราฟในเล่ม
รัน:  python scripts/report.py
"""
import csv
import os
import sqlite3
import statistics
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "detect.db")
RUNS = os.path.join(ROOT, "data", "runs.csv")
OUT = os.path.join(ROOT, "data", "results")


def ts(s):
    """แปลงเวลา ISO (ตัด nanosecond เหลือ microsecond) -> datetime"""
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest[:-6], rest[-6:]
        s = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    return datetime.fromisoformat(s)


def tech_match(rule_techs, tech):
    """T1543 ตรงกับ T1543.001 และกลับกัน"""
    for t in (rule_techs or "").split(","):
        if t and (t == tech or t.startswith(tech + ".") or tech.startswith(t + ".")):
            return True
    return False


def pct(values, p):
    v = sorted(values)
    k = max(0, min(len(v) - 1, round(p / 100 * (len(v) - 1))))
    return v[k]


def main():
    db = sqlite3.connect(DB)
    events = [(ts(t),) for (t,) in db.execute("SELECT ts_event FROM events WHERE ts_event IS NOT NULL")]
    alerts = [dict(rule_id=r, technique=tq, ts_event=ts(te), ts_alert=ts(ta))
              for r, tq, te, ta in db.execute("SELECT rule_id, technique, ts_event, ts_alert FROM alerts")]
    with open(RUNS, encoding="utf-8") as f:
        runs = list(csv.DictReader(f))

    os.makedirs(OUT, exist_ok=True)
    rows, lat_all = [], []
    tp_alerts = 0
    for run in runs:
        if run["technique"] == "BASELINE":
            continue
        a, b = ts(run["start_utc"]), ts(run["end_utc"])
        n_ev = sum(1 for (t,) in events if a <= t <= b)
        in_win = [x for x in alerts if a <= x["ts_event"] <= b]
        hit = [x for x in in_win if tech_match(x["technique"], run["technique"])]
        tp_alerts += len(hit)
        lats = [(x["ts_alert"] - x["ts_event"]).total_seconds() * 1000 for x in hit]
        lat_all += lats
        status = "Detected" if hit else ("Visible-Not-Detected?" if n_ev > 20 else "Not-Visible?")
        rows.append(dict(technique=run["technique"], set=run["set"], events=n_ev,
                         alerts_in_window=len(in_win), matching_alerts=len(hit),
                         rules=" ".join(sorted({x["rule_id"] for x in hit})),
                         min_latency_ms=round(min(lats), 1) if lats else "", status=status))

    with open(os.path.join(OUT, "per_technique.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["technique"])
        w.writeheader()
        w.writerows(rows)

    print(f"{'technique':12} {'set':6} {'events':>7} {'match':>6}  status")
    for r in rows:
        print(f"{r['technique']:12} {r['set']:6} {r['events']:>7} {r['matching_alerts']:>6}  {r['status']}  {r['rules']}")

    print("\n=== Detection Rate (TP / (TP+FN)) ===")
    for grp in ("dev", "eval", "manual"):
        g = [r for r in rows if r["set"] == grp]
        if g:
            d = sum(r["status"] == "Detected" for r in g)
            print(f"  {grp:6}: {d}/{len(g)} = {d / len(g):.1%}")

    if lat_all:
        print("\n=== Detection Latency (ms) ===")
        print(f"  median {statistics.median(lat_all):.1f}   P95 {pct(lat_all, 95):.1f}   max {max(lat_all):.1f}   (n={len(lat_all)})")

    fp_total = 0
    base_hours = 0.0
    for run in runs:
        if run["technique"] != "BASELINE":
            continue
        a, b = ts(run["start_utc"]), ts(run["end_utc"])
        base_hours += (b - a).total_seconds() / 3600
        fp_total += sum(1 for x in alerts if a <= x["ts_event"] <= b)
    if base_hours:
        print("\n=== False Positive ในช่วงใช้งานปกติ (BASELINE) ===")
        print(f"  {fp_total} alert ใน {base_hours:.2f} ชม. = {fp_total / base_hours:.2f} alert/ชม.")
        denom = tp_alerts + fp_total
        if denom:
            print(f"  Precision (นับระดับ alert) = {tp_alerts}/{denom} = {tp_alerts / denom:.1%}")

    # ผลตัดสินจาก Dashboard (หน้า Alerts) — Precision ที่แม่นกว่าเพราะคนตรวจเอง
    # Dashboard เก็บเป็นรหัสสั้น "tp" / "fp" (ดู VERDICT ใน dashboard/app.py)
    try:
        vdb = sqlite3.connect(os.path.join(ROOT, "data", "verdicts.db"))
        v = dict(vdb.execute("SELECT verdict, COUNT(*) FROM alert_verdicts GROUP BY verdict").fetchall())
        tp, fp = v.get("tp", 0), v.get("fp", 0)
        if tp + fp:
            print("\n=== ผลตัดสินของผู้วิเคราะห์ (จาก Dashboard) ===")
            print(f"  True Positive {tp}   False Positive {fp}   Precision = {tp / (tp + fp):.1%}")
    except sqlite3.OperationalError:
        pass

    print(f"\nบันทึก CSV ไว้ที่ {OUT}/per_technique.csv")
    print("หมายเหตุ: สถานะที่มี ? ต้องเปิดดู event ในช่วงเวลานั้นด้วยตาก่อนสรุปลงเล่ม")


if __name__ == "__main__":
    main()
