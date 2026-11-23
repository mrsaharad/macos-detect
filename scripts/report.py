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


def wilson(k, n, z=1.96):
    """ช่วงความเชื่อมั่น 95% ของสัดส่วน k/n แบบ Wilson score (เหมาะกับตัวอย่างน้อย)"""
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {k / n:.1%} (95% CI {lo:.1%}–{hi:.1%})"


def rate_json(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4), "ci95": [round(lo, 4), round(hi, 4)]}


# tactic ของเทคนิคที่ไม่มีกฎรองรับ (ตาม ATT&CK v19) — เทคนิคที่มีกฎใช้ tactic จากแท็กในไฟล์กฎ
TACTIC_NO_RULE = {"T1033": "discovery", "T1057": "discovery", "T1083": "discovery", "T1201": "discovery",
                  "T1217": "discovery", "T1105": "command_and_control"}
TACTIC_ORDER = ["execution", "persistence", "credential_access", "discovery", "stealth",
                "defense_impairment", "command_and_control"]


def rule_tactics(rules):
    """technique -> tactic จากแท็กของกฎ (T1518 ใช้กับ T1518.001 ได้)"""
    out = {}
    for r in rules:
        for t in filter(None, r.technique.split(",")):
            out[t] = r.tactic.split(",")[0]
    return out


def tactic_of(tech, by_rule):
    return by_rule.get(tech) or by_rule.get(tech.split(".")[0]) or TACTIC_NO_RULE.get(tech, "?")


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
            summary[grp] = rate_json(d, len(g))
            print(f"  Detection Rate {grp:6}: {rate(d, len(g))}")
    return summary, lat_all, tp_final


def num(r, k):
    return int(r.get(k) or 0)


def test_level(by_rule):
    if not os.path.exists(PER_TEST):
        return {}, []
    with open(PER_TEST, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print("\n=== 2. ระดับ test (ตรวจด้วยตาทีละ test: attacksim/per_test_results.csv) ===")
    out = {}
    for name, sets in (("dev", {"dev"}), ("eval+manual", {"eval", "manual"})):
        g = [r for r in rows if r["set"] in sets]
        n = sum(num(r, "tests") for r in g)
        vis = sum(num(r, "visible") for r in g)
        det = sum(num(r, "detected") for r in g)
        res = {"tests": n, "visibility": rate_json(vis, n), "detection": rate_json(det, n)}
        print(f"  {name}:")
        print(f"    Visibility {rate(vis, n)}")
        print(f"    Detection  {rate(det, n)}")
        if name == "dev":
            before = sum(num(r, "detected_before_tuning") for r in g)
            res["detection_before_tuning"] = rate_json(before, n)
            print(f"    ก่อนปรับกฎ {rate(before, n)}")
        else:
            # technique ที่อยู่ในขอบเขตกฎ = มีกฎที่ตั้งใจจับ technique นั้น
            scope = [r for r in g if not r["missed_reason"].startswith("ไม่มีกฎ")]
            sn = sum(num(r, "tests") for r in scope)
            sd = sum(num(r, "detected") for r in scope)
            st = sum(num(r, "detected") > 0 for r in scope)
            res["in_scope"] = {"techniques": rate_json(st, len(scope)), "tests": rate_json(sd, sn)}
            print(f"    เฉพาะ technique ที่มีกฎรองรับ: technique {rate(st, len(scope))}")
            print(f"    {'':30}test {rate(sd, sn)}")
            # ระดับการตรวจจับแบบ MITRE ATT&CK Evaluations
            other = sum(num(r, "detected_other_technique") for r in g)
            cats = {"Technique": det - other, "General": other, "Telemetry": vis - det, "None": n - vis}
            res["mitre_categories"] = cats
            print("    ระดับการตรวจจับ (MITRE Evaluations): "
                  + "  ".join(f"{k} {v}" for k, v in cats.items())
                  + "   [General = มี alert แต่เป็นกฎของเทคนิคอื่น]")
        out[name] = res

    # Detection Rate แยกตาม tactic (ตาราง 2.3 ของเล่มสัญญาไว้)
    print("\n=== 2b. Detection Rate ระดับ test แยกตาม tactic (eval+manual / dev หลังปรับกฎ) ===")
    per_tac = {}
    for r in rows:
        tac = tactic_of(r["technique"], by_rule)
        grp = "dev" if r["set"] == "dev" else "eval+manual"
        d = per_tac.setdefault(tac, {}).setdefault(grp, [0, 0, 0, 0])   # test, detected, technique, technique-detected
        d[0] += num(r, "tests")
        d[1] += num(r, "detected")
        d[2] += 1
        d[3] += num(r, "detected") > 0
    out["per_tactic"] = {}
    print(f"  {'tactic':20} {'eval+manual (test)':>34}   {'dev หลังปรับ (test)':>20}")
    for tac in sorted(per_tac, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99):
        cells, js = [], {}
        for grp in ("eval+manual", "dev"):
            d = per_tac[tac].get(grp)
            if d:
                lo, hi = wilson(d[1], d[0])
                cells.append(f"{d[1]}/{d[0]} = {d[1] / d[0]:.0%} [{lo:.0%}–{hi:.0%}]")
                js[grp] = {"tests": rate_json(d[1], d[0]), "techniques": rate_json(d[3], d[2])}
            else:
                cells.append("—")
        out["per_tactic"][tac] = js
        print(f"  {tac:20} {cells[0]:>34}   {cells[1]:>20}")
    return out, rows


def navigator_layer(rules, rows, by_rule):
    """ไฟล์ layer สำหรับเปิดใน ATT&CK Navigator (รูปที่ 4.1): สีตามผลทดสอบ"""
    tested = {}
    for r in rows:
        t = tested.setdefault(r["technique"], [0, 0, set()])
        t[0] += num(r, "tests")
        t[1] += num(r, "detected")
        t[2].add(r["set"])
    rule_ids = defaultdict(list)
    for r in rules:
        for t in filter(None, r.technique.split(",")):
            rule_ids[t].append(r.id)
    colors = {"detected": "#5aa469", "partial": "#f2c94c", "missed_rule": "#f2994a",
              "no_rule": "#eb5757", "untested": "#9ec5fe"}
    techs = []
    for tech in sorted(set(tested) | set(rule_ids)):
        ids = rule_ids.get(tech) or rule_ids.get(tech.split(".")[0], [])
        if tech in tested:
            n, d, sets = tested[tech]
            kind = ("detected" if d == n else "partial" if d else ("missed_rule" if ids else "no_rule"))
            comment = f"{'/'.join(sorted(sets))}: ตรวจจับ {d}/{n} test"
            score = round(100 * d / n)
        else:
            kind, comment, score = "untested", "มีกฎแต่ไม่ได้ทดสอบ", None
        if ids:
            comment += f"; กฎ {', '.join(ids)}"
        item = {"techniqueID": tech, "tactic": tactic_of(tech, by_rule).replace("_", "-"),
                "color": colors[kind], "comment": comment, "enabled": True, "showSubtechniques": True}
        if score is not None:
            item["score"] = score
        techs.append(item)
    layer = {
        "name": "macOS Detect — coverage", "versions": {"attack": "19", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "ผลทดสอบกฎ 26 ข้อด้วย Atomic Red Team (dev หลังปรับกฎ + eval + manual)",
        "filters": {"platforms": ["macOS"]}, "hideDisabled": False, "techniques": techs,
        "legendItems": [{"label": "ตรวจจับได้ทุก test", "color": colors["detected"]},
                        {"label": "ตรวจจับได้บาง test", "color": colors["partial"]},
                        {"label": "มีกฎแต่ตรวจจับไม่ได้", "color": colors["missed_rule"]},
                        {"label": "ไม่มีกฎรองรับ", "color": colors["no_rule"]},
                        {"label": "มีกฎแต่ไม่ได้ทดสอบ", "color": colors["untested"]}],
        "showTacticRowBackground": True, "selectSubtechniquesWithParent": False,
    }
    path = os.path.join(OUT, "navigator_layer.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, ensure_ascii=False, indent=2)
    print(f"\nATT&CK Navigator layer: {path}  (เปิดที่ mitre-attack.github.io/attack-navigator → Open Existing Layer)")


def baseline_fp(alerts, events_by_id, runs, tp_final):
    """FP ในช่วง BASELINE แยกตามชุด: pilot = รอบนำร่อง 60 นาที (22 พ.ย.), baseline = รอบหลัก 8 ชม."""
    sets = defaultdict(lambda: {"hours": 0.0, "rows": []})
    for run in runs:
        if run["technique"] != "BASELINE":
            continue
        a, b = ts(run["start_utc"]), ts(run["end_utc"])
        g = sets[run["set"]]
        g["hours"] += (b - a).total_seconds() / 3600
        for x in alerts:
            if a <= x["ts_event"] <= b:
                e = events_by_id.get(x["event_id"], {})
                g["rows"].append(dict(set=run["set"], rule_id=x["rule_id"], ts_event=x["ts_event"].isoformat(),
                                      parent=e.get("ParentImage"), image=e.get("Image"),
                                      command=e.get("CommandLine")))
    if not sets:
        return {}, {}
    write_csv("baseline_alerts.csv", [r for g in sets.values() for r in g["rows"]])
    out = {}
    for name in sorted(sets, key=lambda n: n != "baseline"):          # รอบหลักก่อน
        g = sets[name]
        fp, hours = len(g["rows"]), g["hours"]
        upper = poisson_upper(fp)
        print(f"\n=== 4. False Positive ช่วงใช้งานปกติ [{name}] ({hours * 60:.0f} นาที) ===")
        print(f"  {fp} alert = {fp / hours:.2f} alert/ชม.  (ขอบบน 95%: ≤ {upper / hours:.2f} alert/ชม.)"
              f"  ≈ {fp / hours * 8:.1f} alert ต่อวันทำงาน 8 ชม.")
        by_rule = Counter(f"{r['rule_id']}  {base(r['parent'])} -> {base(r['image'])}" for r in g["rows"])
        for k, n in by_rule.most_common(10):
            print(f"    {n:>3} × {k}")
        res = {"hours": round(hours, 2), "alerts": fp, "fp_per_hour": round(fp / hours, 2),
               "fp_per_hour_upper95": round(upper / hours, 2),
               "by_rule": dict(Counter(r["rule_id"] for r in g["rows"]))}
        out[name] = res
    main = out.get("baseline") or next(iter(out.values()))
    fp = main["alerts"]
    if tp_final + fp:
        main["precision"] = [tp_final, tp_final + fp]
        print("\n=== 5. Precision ระดับ alert (alert ที่ตรง technique ใน eval+manual / + FP baseline รอบหลัก) ===")
        print(f"  {tp_final}/{tp_final + fp} = {tp_final / (tp_final + fp):.1%}"
              "  (ขึ้นกับสัดส่วนเวลาทดสอบกับเวลาใช้งานปกติ — ใช้ FP ต่อชั่วโมงเป็นตัวเลขหลัก)")
    return main, out


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
    out = {}
    for tag, title in (("overhead", "System Overhead ช่วง baseline"), ("overhead_pilot60", "System Overhead รอบนำร่อง 60 นาที"),
                       ("stability", "ทดสอบความเสถียรต่อเนื่อง")):
        path = os.path.join(OUT, f"{tag}_summary.json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
        out[tag] = s
        c, r = s["cpu_pct"], s["rss_mb"]
        print(f"\n=== 7. {title} ({s['minutes']} นาที, วัดทุก {s['interval_s']:g} วินาที, {s['samples']} ครั้ง; CPU% ต่อ 1 คอร์) ===")
        print(f"  {'':10} {'CPU เฉลี่ย':>10} {'median':>7} {'P95':>6} {'max':>7}   {'RAM เฉลี่ย':>10} {'max':>6}")
        for k in ("collector", "eslogger", "total"):
            print(f"  {k:10} {c[k]['mean']:>9}% {c[k]['median']:>6}% {c[k]['p95']:>5}% {c[k]['max']:>6}%"
                  f"   {r[k]['mean']:>8} MB {r[k]['max']:>4} MB")
        print(f"  event {s['events']:,} รายการ ({s.get('events_per_sec')}/วินาที)  ฐานข้อมูลโต {s['db_growth_mb']} MB"
              f" (≈ {s['db_growth_mb'] / s['minutes'] * 60 * 24 / 1024:.1f} GB/วัน)")
        if "planned_minutes" in s:
            ok = s.get("sensor_stopped_at") is None and s["minutes"] >= s["planned_minutes"] - 1
            print(f"  ทำงานต่อเนื่องครบตามแผน ({s['planned_minutes']:g} นาที): {'ใช่' if ok else 'ไม่ใช่'}"
                  + (f" — หยุดเมื่อ {s['sensor_stopped_at']}" if s.get("sensor_stopped_at") else ""))
    return out


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

    rules = load_rules(os.path.join(ROOT, "rules"))
    by_rule = rule_tactics(rules)
    result = {}
    result["technique_level"], lat_all, tp_final = technique_level(events, alerts, runs)
    result["test_level"], test_rows = test_level(by_rule)
    if test_rows:
        navigator_layer(rules, test_rows, by_rule)
    if lat_all:
        print("\n=== 3. Detection Latency (เวลาเกิดเหตุ -> ออก alert, ms) ===")
        print(f"  median {statistics.median(lat_all):.1f}   P95 {pct(lat_all, 95):.1f}   max {max(lat_all):.1f}   (n={len(lat_all)})")
        result["latency_ms"] = {"median": round(statistics.median(lat_all), 1), "p95": round(pct(lat_all, 95), 1),
                                "max": round(max(lat_all), 1), "n": len(lat_all)}
    result["baseline"], result["baseline_sets"] = baseline_fp(alerts, events_by_id, runs, tp_final)

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
