"""
คำนวณผลสำหรับบทที่ 4 จาก data/detect.db + data/runs.csv (+ attacksim/per_test_results.csv)

runs.csv = ช่วงเวลาที่รันแต่ละ technique (ground truth) และช่วง BASELINE (ใช้เครื่องปกติ)
ผลที่ได้:
  1. ระดับ technique (อัตโนมัติจากช่วงเวลา)
      Detected               = มี alert ของ technique นั้นในช่วงเวลา
      Visible-Not-Detected?  = มี event ในช่วงเวลา แต่ไม่มี alert ที่ตรง
      Not-Visible?           = แทบไม่มี event ในช่วงเวลา
  2. ระดับ test (จาก attacksim/per_test_results.csv ซึ่งตรวจด้วยตาทีละ test จาก log + event
     เพราะ Invoke-AtomicTest ไม่บันทึกเวลาของแต่ละ test จึงแยกอัตโนมัติไม่ได้)
  3. Latency (median / P95 / max) ของ alert ที่ตรง technique
  4. False Positive ต่อชั่วโมงในช่วง BASELINE + ขอบบนที่ความเชื่อมั่น 95% (Poisson)
  5. Precision ระดับ alert ของกฎชุดสุดท้าย (eval + manual เทียบกับ baseline)
  6. รันกฎชุดสุดท้ายย้อนหลังกับ event ทุกช่วงที่ไม่ใช่การทดสอบ (retrospective replay)
  7. System Overhead (CPU/RAM) จาก data/results/overhead_summary.json
บันทึกผลเป็น CSV/JSON ใน data/results/ เพื่อนำไปทำตาราง/กราฟในเล่ม
รัน:  python scripts/report.py
"""
import csv
import json
import math
import os
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine.rules import load_rules   # noqa: E402

DB = os.path.join(ROOT, "data", "detect.db")
RUNS = os.path.join(ROOT, "data", "runs.csv")
TRIAL_RUNS = os.path.join(ROOT, "data", "runs_trial_T1082_old-rule.csv")
PER_TEST = os.path.join(ROOT, "attacksim", "per_test_results.csv")
OUT = os.path.join(ROOT, "data", "results")
SESSION_PAD = timedelta(minutes=10)     # เผื่อช่วง prereq/cleanup ก่อน-หลังการทดสอบแต่ละชุด
FIELDS = ("event_type", "pid", "ppid", "Image", "ParentImage", "CommandLine",
          "TargetFilename", "SourceFilename", "SigningId", "User")


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


def poisson_upper(k, conf=0.95):
    """ขอบบนของค่าเฉลี่ย Poisson เมื่อนับได้ k ครั้ง (k=0 -> ~3.0 = rule of three)"""
    def cdf(lam):
        return sum(math.exp(-lam) * lam ** i / math.factorial(i) for i in range(k + 1))
    lo, hi = 0.0, 100.0 + 10 * k
    for _ in range(100):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if cdf(mid) > 1 - conf else (lo, mid)
    return hi


def base(path):
    return os.path.basename(path or "") or "-"


def read_runs(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(name, rows):
    if not rows:
        return
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def technique_level(events, alerts, runs):
    rows, lat_all, tp_final = [], [], 0
    for run in runs:
        if run["technique"] == "BASELINE":
            continue
        a, b = ts(run["start_utc"]), ts(run["end_utc"])
        n_ev = sum(1 for t in events if a <= t <= b)
        in_win = [x for x in alerts if a <= x["ts_event"] <= b]
        hit = [x for x in in_win if tech_match(x["technique"], run["technique"])]
        if run["set"] in ("eval", "manual"):
            tp_final += len(hit)
        lats = [(x["ts_alert"] - x["ts_event"]).total_seconds() * 1000 for x in hit]
        lat_all += lats
        status = "Detected" if hit else ("Visible-Not-Detected?" if n_ev > 20 else "Not-Visible?")
        rows.append(dict(technique=run["technique"], set=run["set"], events=n_ev,
                         alerts_in_window=len(in_win), matching_alerts=len(hit),
                         rules=" ".join(sorted({x["rule_id"] for x in hit})),
                         min_latency_ms=round(min(lats), 1) if lats else "", status=status))
    write_csv("per_technique.csv", rows)

    print("=== 1. ระดับ technique (อัตโนมัติจากช่วงเวลา) ===")
    print(f"{'technique':12} {'set':6} {'events':>7} {'match':>6}  status")
    for r in rows:
        print(f"{r['technique']:12} {r['set']:6} {r['events']:>7} {r['matching_alerts']:>6}  {r['status']}  {r['rules']}")
    summary = {}
    for grp in ("dev", "eval", "manual"):
        g = [r for r in rows if r["set"] == grp]
        if g:
            d = sum(r["status"] == "Detected" for r in g)
            summary[grp] = [d, len(g)]
            print(f"  Detection Rate {grp:6}: {d}/{len(g)} = {d / len(g):.1%}")
    ev = summary.get("eval", [0, 0])
    mn = summary.get("manual", [0, 0])
    if mn[1]:
        d, n = ev[0] + mn[0], ev[1] + mn[1]
        summary["eval+manual"] = [d, n]
        print(f"  Detection Rate eval+manual: {d}/{n} = {d / n:.1%}")
    return summary, lat_all, tp_final


def test_level():
    if not os.path.exists(PER_TEST):
        return {}
    with open(PER_TEST, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print("\n=== 2. ระดับ test (ตรวจด้วยตาทีละ test: attacksim/per_test_results.csv) ===")
    out = {}
    for name, sets in (("dev", {"dev"}), ("eval+manual", {"eval", "manual"})):
        g = [r for r in rows if r["set"] in sets]
        n = sum(int(r["tests"]) for r in g)
        vis = sum(int(r["visible"]) for r in g)
        det = sum(int(r["detected"]) for r in g)
        res = {"tests": n, "visible": vis, "detected": det}
        line = f"  {name:12}: test {n}  Visibility {vis}/{n} = {vis / n:.1%}  Detection {det}/{n} = {det / n:.1%}"
        if name == "dev":
            before = sum(int(r["detected_before_tuning"]) for r in g)
            res["detected_before_tuning"] = before
            line += f"  (ก่อนปรับกฎ {before}/{n} = {before / n:.1%})"
        else:
            # technique ที่อยู่ในขอบเขตกฎ = มีกฎที่ตั้งใจจับ technique นั้น
            scope = [r for r in g if not r["missed_reason"].startswith("ไม่มีกฎ")]
            sn = sum(int(r["tests"]) for r in scope)
            sd = sum(int(r["detected"]) for r in scope)
            st = sum(int(r["detected"]) > 0 for r in scope)
            res["in_scope"] = {"techniques": [st, len(scope)], "tests": [sd, sn]}
            line += (f"\n  {'':12}  เฉพาะ technique ที่มีกฎรองรับ: technique {st}/{len(scope)} = {st / len(scope):.1%}"
                     f"  test {sd}/{sn} = {sd / sn:.1%}")
        out[name] = res
        print(line)
    return out


def baseline_fp(alerts, events_by_id, runs, tp_final):
    fp, hours, rows = 0, 0.0, []
    for run in runs:
        if run["technique"] != "BASELINE":
            continue
        a, b = ts(run["start_utc"]), ts(run["end_utc"])
        hours += (b - a).total_seconds() / 3600
        for x in alerts:
            if a <= x["ts_event"] <= b:
                fp += 1
                e = events_by_id.get(x["event_id"], {})
                rows.append(dict(rule_id=x["rule_id"], ts_event=x["ts_event"].isoformat(),
                                 parent=e.get("ParentImage"), image=e.get("Image"),
                                 command=e.get("CommandLine")))
    if not hours:
        return {}
    write_csv("baseline_alerts.csv", rows)
    upper = poisson_upper(fp)
    print(f"\n=== 4. False Positive ในช่วงใช้งานปกติ (BASELINE {hours * 60:.0f} นาที) ===")
    print(f"  {fp} alert = {fp / hours:.2f} alert/ชม.  (ขอบบน 95%: ≤ {upper / hours:.2f} alert/ชม.)")
    for r in rows:
        print(f"    {r['rule_id']}  {base(r['parent'])} -> {(r['command'] or '')[:70]}")
    res = {"hours": round(hours, 2), "alerts": fp, "fp_per_hour": round(fp / hours, 2),
           "fp_per_hour_upper95": round(upper / hours, 2)}
    denom = tp_final + fp
    if denom:
        res["precision"] = [tp_final, denom]
        print(f"\n=== 5. Precision ระดับ alert (กฎชุดสุดท้าย: alert ที่ตรง technique ใน eval+manual / + FP baseline) ===")
        print(f"  {tp_final}/{denom} = {tp_final / denom:.1%}")
    return res


def test_sessions(runs):
    """ช่วงเวลาที่มีการทดสอบ (รวมแต่ละชุดเป็นช่วงเดียว + เผื่อ prereq/cleanup)"""
    by_set = defaultdict(list)
    for run in runs:
        if run["technique"] != "BASELINE":
            by_set[run["set"]].append((ts(run["start_utc"]), ts(run["end_utc"])))
    return [(min(a for a, _ in w) - SESSION_PAD, max(b for _, b in w) + SESSION_PAD) for w in by_set.values()]


def replay(db, runs):
    """รันกฎชุดสุดท้ายกับ event ทุกช่วงที่ไม่ใช่การทดสอบและไม่ใช่ baseline"""
    rules = load_rules(os.path.join(ROOT, "rules"))
    excluded = test_sessions(runs + read_runs(TRIAL_RUNS))
    excluded += [(ts(r["start_utc"]), ts(r["end_utc"])) for r in runs if r["technique"] == "BASELINE"]
    minutes, hits = set(), []
    cols = ", ".join(("ts_event",) + FIELDS)
    for row in db.execute(f"SELECT {cols} FROM events WHERE ts_event IS NOT NULL ORDER BY id"):
        t = ts(row[0])
        if any(a <= t <= b for a, b in excluded):
            continue
        minutes.add(row[0][:16])
        rec = dict(zip(FIELDS, row[1:]))
        for r in rules:
            if r.matches(rec):
                hits.append(dict(rule_id=r.id, ts_event=row[0], parent=rec["ParentImage"],
                                 image=rec["Image"], command=rec["CommandLine"] or rec["TargetFilename"]))
    hours = len(minutes) / 60
    write_csv("replay_alerts.csv", hits)
    print(f"\n=== 6. รันกฎชุดสุดท้ายย้อนหลัง (ช่วงที่ไม่ได้ทดสอบ: เครื่องเปิด collector อยู่ {hours:.1f} ชม.) ===")
    print(f"  {len(hits)} alert = {len(hits) / hours:.2f} alert/ชม.  (มีงานพัฒนาโปรเจคปนอยู่ ไม่ใช่การใช้งานปกติล้วน)")
    by_rule = defaultdict(Counter)
    for h in hits:
        by_rule[h["rule_id"]][f"{base(h['parent'])} -> {base(h['image'])}"] += 1
    for rid, c in sorted(by_rule.items(), key=lambda kv: -sum(kv[1].values())):
        top = ", ".join(f"{k} ({n})" for k, n in c.most_common(3))
        print(f"    {rid}: {sum(c.values()):>4}   {top}")
    return {"hours": round(hours, 2), "alerts": len(hits), "fp_per_hour": round(len(hits) / hours, 2) if hours else None,
            "by_rule": {rid: sum(c.values()) for rid, c in by_rule.items()}}


def overhead():
    path = os.path.join(OUT, "overhead_summary.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        s = json.load(f)
    c, r = s["cpu_pct"], s["rss_mb"]
    print(f"\n=== 7. System Overhead ({s['minutes']} นาที, วัดทุก {s['interval_s']:g} วินาที, {s['samples']} ครั้ง; CPU% ต่อ 1 คอร์) ===")
    print(f"  {'':10} {'CPU เฉลี่ย':>10} {'median':>7} {'P95':>6} {'max':>7}   {'RAM เฉลี่ย':>10} {'max':>6}")
    for k in ("collector", "eslogger", "total"):
        print(f"  {k:10} {c[k]['mean']:>9}% {c[k]['median']:>6}% {c[k]['p95']:>5}% {c[k]['max']:>6}%"
              f"   {r[k]['mean']:>8} MB {r[k]['max']:>4} MB")
    print(f"  event {s['events']:,} รายการ ({s.get('events_per_sec')}/วินาที)  ฐานข้อมูลโต {s['db_growth_mb']} MB"
          f" (≈ {s['db_growth_mb'] / s['minutes'] * 60 * 24 / 1024:.1f} GB/วัน)")
    return s


def main():
    db = sqlite3.connect(DB)
    events = [ts(t) for (t,) in db.execute("SELECT ts_event FROM events WHERE ts_event IS NOT NULL")]
    alerts = [dict(event_id=i, rule_id=r, technique=tq, ts_event=ts(te), ts_alert=ts(ta))
              for i, r, tq, te, ta in db.execute("SELECT event_id, rule_id, technique, ts_event, ts_alert FROM alerts")]
    ids = [x["event_id"] for x in alerts]
    events_by_id = {}
    if ids:
        q = f"SELECT id, Image, ParentImage, CommandLine FROM events WHERE id IN ({','.join('?' * len(ids))})"
        events_by_id = {i: dict(Image=im, ParentImage=pi, CommandLine=cl) for i, im, pi, cl in db.execute(q, ids)}
    runs = read_runs(RUNS)
    os.makedirs(OUT, exist_ok=True)

    result = {}
    result["technique_level"], lat_all, tp_final = technique_level(events, alerts, runs)
    result["test_level"] = test_level()
    if lat_all:
        print("\n=== 3. Detection Latency (เวลาเกิดเหตุ -> ออก alert, ms) ===")
        print(f"  median {statistics.median(lat_all):.1f}   P95 {pct(lat_all, 95):.1f}   max {max(lat_all):.1f}   (n={len(lat_all)})")
        result["latency_ms"] = {"median": round(statistics.median(lat_all), 1), "p95": round(pct(lat_all, 95), 1),
                                "max": round(max(lat_all), 1), "n": len(lat_all)}
    result["baseline"] = baseline_fp(alerts, events_by_id, runs, tp_final)

    # ผลตัดสินจาก Dashboard (หน้า Alerts) — Dashboard เก็บเป็นรหัสสั้น "tp" / "fp"
    try:
        vdb = sqlite3.connect(os.path.join(ROOT, "data", "verdicts.db"))
        v = dict(vdb.execute("SELECT verdict, COUNT(*) FROM alert_verdicts GROUP BY verdict").fetchall())
        tp, fp = v.get("tp", 0), v.get("fp", 0)
        if tp + fp:
            print("\n=== ผลตัดสินของผู้วิเคราะห์ (จาก Dashboard) ===")
            print(f"  True Positive {tp}   False Positive {fp}   Precision = {tp / (tp + fp):.1%}")
            result["analyst_verdicts"] = {"tp": tp, "fp": fp}
    except sqlite3.OperationalError:
        pass

    result["replay"] = replay(db, runs)
    result["overhead"] = overhead()
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, default=str)

    print(f"\nบันทึกไว้ที่ {OUT}/ (per_technique.csv, baseline_alerts.csv, replay_alerts.csv, summary.json)")
    print("หมายเหตุ: สถานะที่มี ? ในข้อ 1 ต้องเปิดดู event ในช่วงเวลานั้นด้วยตาก่อนสรุปลงเล่ม")


if __name__ == "__main__":
    main()
