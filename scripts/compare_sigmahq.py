"""
เทียบกฎของโครงงาน (rules/) กับกฎ macOS ของ SigmaHQ บน event ชุดเดียวกันที่เก็บไว้ใน data/detect.db
(รันกฎทั้งสองชุดย้อนหลังด้วย engine เดียวกัน จึงเทียบเฉพาะ "กฎ" ไม่ได้เทียบ engine)

ช่วงที่ใช้
  - ช่วงทดสอบแต่ละเทคนิคใน data/runs.csv (dev / eval) → เทคนิคที่ตรวจจับได้
    (dev ไม่ยุติธรรมกับ SigmaHQ เพราะกฎของเราปรับจากชุดนี้ ให้ดู eval เป็นหลัก)
  - ช่วง evasion test (data/evasion_runs.csv, version v1) → variant ที่ตรวจจับได้
  - ช่วงที่ไม่ได้ทดสอบ (เหมือน report.py ข้อ 6) + ช่วง baseline → การแจ้งเตือนเท็จต่อชั่วโมง
ข้อจำกัด: กฎ SigmaHQ บางข้อใช้ฟิลด์ที่ระบบเราไม่มี (OriginalFileName, ParentCommandLine) เงื่อนไขนั้นจึงไม่ตรงเสมอ
SigmaHQ ยังใช้เลขเทคนิคก่อน ATT&CK v19 จึงเทียบ T1685 = T1562.001 และ T1686 = T1562.004

ต้องมี data/third_party/sigma (git clone --depth 1 https://github.com/SigmaHQ/sigma.git data/third_party/sigma)
รัน:  python scripts/compare_sigmahq.py      ผล: data/results/compare_sigmahq.json + .csv
"""
import csv
import glob
import json
import os
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import yaml  # noqa: E402
from engine.rules import Rule, load_rules  # noqa: E402
from report import (DB, EVASION, FIELDS, OUT, RUNS, STRESS_RUNS, TRIAL_RUNS, read_runs, tech_match,  # noqa: E402
                    test_sessions, ts)

SIGMA = os.path.join(ROOT, "data", "third_party", "sigma")
ALIAS = {"T1685": "T1562.001", "T1686": "T1562.004"}


def load_sigmahq():
    rules = []
    for f in sorted(glob.glob(os.path.join(SIGMA, "rules", "macos", "**", "*.yml"), recursive=True)):
        with open(f, encoding="utf-8") as fh:
            d = yaml.safe_load(fh)
        r = Rule(d, f)
        r.id = os.path.basename(f)[:-4]
        r.level = d.get("level", "")
        rules.append(r)
    return rules


def match_tech(rule, tech):
    return tech_match(rule.technique, tech) or tech_match(rule.technique, ALIAS.get(tech, ""))


def events_between(db, a, b):
    cols = ", ".join(FIELDS)
    q = f"SELECT {cols} FROM events WHERE ts_event >= ? AND ts_event <= ?"
    return [dict(zip(FIELDS, row)) for row in db.execute(q, (a.strftime("%Y-%m-%dT%H:%M:%S"), b.isoformat()))]


def hits(rules, recs):
    return [(r, rec) for rec in recs for r in rules if r.matches(rec)]


def main():
    if not os.path.isdir(SIGMA):
        sys.exit("ไม่พบ data/third_party/sigma — git clone ก่อน (ดูหัวไฟล์)")
    commit = subprocess.run(["git", "-C", SIGMA, "log", "-1", "--format=%h %cs"], capture_output=True,
                            text=True).stdout.strip()
    sets = {"ours": load_rules(os.path.join(ROOT, "rules")), "sigmahq": load_sigmahq()}
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    runs = read_runs(RUNS)
    result = {"sigmahq_commit": commit, "rules": {k: len(v) for k, v in sets.items()}}
    print(f"กฎของเรา {len(sets['ours'])} ข้อ  vs  SigmaHQ macOS {len(sets['sigmahq'])} ข้อ (commit {commit})")

    # ---- 1) เทคนิคที่ตรวจจับได้ในช่วงทดสอบ ----
    per_tech = []
    for run in runs:
        if run["technique"] == "BASELINE":
            continue
        recs = events_between(db, ts(run["start_utc"]), ts(run["end_utc"]))
        row = {"technique": run["technique"], "set": run["set"]}
        for name, rules in sets.items():
            h = hits(rules, recs)
            good = sorted({r.id for r, _ in h if match_tech(r, run["technique"])})
            row[f"{name}_detected"] = bool(good)
            row[f"{name}_rules"] = " ".join(good)
            row[f"{name}_any_alert"] = bool(h)
        per_tech.append(row)
    print("\n=== เทคนิคที่ตรวจจับได้ (alert ที่กำกับเทคนิคตรงกัน) ===")
    result["detection"] = {}
    for grp in ("dev", "eval"):
        g = [r for r in per_tech if r["set"] == grp]
        both = sum(r["ours_detected"] and r["sigmahq_detected"] for r in g)
        line = {k: sum(r[f"{k}_detected"] for r in g) for k in sets}
        union = sum(r["ours_detected"] or r["sigmahq_detected"] for r in g)
        result["detection"][grp] = dict(line, both=both, union=union, n=len(g))
        print(f"  {grp:5}: ของเรา {line['ours']}/{len(g)}  SigmaHQ {line['sigmahq']}/{len(g)}  "
              f"ทั้งคู่ {both}  รวมกัน {union}/{len(g)}")
    for r in per_tech:
        if r["ours_detected"] != r["sigmahq_detected"]:
            print(f"    ต่างกัน: {r['technique']:10} {r['set']:5} ของเรา [{r['ours_rules']}]  SigmaHQ [{r['sigmahq_rules']}]")

    # ---- 2) evasion v1 ----
    ev = [r for r in read_runs(EVASION) if r["version"] == "v1"]
    if ev:
        print("\n=== Evasion variant (v1) ที่มี alert จากกฎแต่ละชุด ===")
        res = {}
        for name, rules in sets.items():
            d_base = d_var = n_base = n_var = 0
            for r in ev:
                h = hits(rules, events_between(db, ts(r["start_utc"]), ts(r["end_utc"])))
                if r["kind"] == "base":
                    n_base += 1
                    d_base += bool(h)
                else:
                    n_var += 1
                    d_var += bool(h)
            res[name] = {"base": [d_base, n_base], "variants": [d_var, n_var]}
            print(f"  {name:8}: base {d_base}/{n_base}  variant {d_var}/{n_var}")
        result["evasion_v1"] = res

    # ---- 3) การแจ้งเตือนในช่วงที่ไม่ได้ทดสอบ ----
    ev_rows = [dict(r, technique=r["id"], set="evasion-" + r["version"]) for r in read_runs(EVASION)]
    st_rows = [dict(r, technique=r["id"], set="stress-" + r["id"] + r["start_utc"]) for r in read_runs(STRESS_RUNS)]
    excluded = test_sessions(runs + read_runs(TRIAL_RUNS) + ev_rows + st_rows)
    minutes, fp = set(), {k: Counter() for k in sets}
    cols = ", ".join(("ts_event",) + FIELDS)
    for row in db.execute(f"SELECT {cols} FROM events WHERE ts_event IS NOT NULL ORDER BY id"):
        t = ts(row[0])
        if any(a <= t <= b for a, b in excluded):
            continue
        minutes.add(row[0][:16])
        rec = dict(zip(FIELDS, row[1:]))
        for name, rules in sets.items():
            for r in rules:
                if r.matches(rec):
                    fp[name][r.id] += 1
    hours = len(minutes) / 60
    print(f"\n=== การแจ้งเตือนช่วงที่ไม่ได้ทดสอบ ({hours:.1f} ชม. รวม baseline) ===")
    result["non_test"] = {"hours": round(hours, 2)}
    for name in sets:
        n = sum(fp[name].values())
        result["non_test"][name] = {"alerts": n, "per_hour": round(n / hours, 2), "by_rule": dict(fp[name])}
        top = ", ".join(f"{k} ({v})" for k, v in fp[name].most_common(5))
        print(f"  {name:8}: {n} alert = {n / hours:.2f}/ชม.   {top}")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "compare_sigmahq.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT, "compare_sigmahq.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(per_tech[0]))
        w.writeheader()
        w.writerows(per_tech)
    print(f"\nบันทึกไว้ที่ {OUT}/compare_sigmahq.json และ .csv")


if __name__ == "__main__":
    main()
