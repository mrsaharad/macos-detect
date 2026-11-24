"""
คัดเลือก Atomic test ชุด eval2 (วัดผล v2) แบบทำซ้ำได้
ประชากร = test สำหรับ macOS ที่ (1) ยังไม่เคยอยู่ใน plan.txt (dev / eval ของ v1)
          (2) executor เป็น sh/bash (รันอัตโนมัติได้) (3) คำสั่งไม่มีรูปแบบเสี่ยง (ลบระบบ, เครือข่าย, ถามรหัสผ่าน)
ลำดับ    = สุ่มด้วย seed 2570 แล้วผู้ทำโครงงานตรวจคำสั่งทีละตัวตามลำดับ ตัวที่ไม่ปลอดภัยข้ามพร้อมเหตุผล
           (บันทึกใน attacksim/eval2_review.md) จนได้ครบจำนวนที่ต้องการ
รัน:  python attacksim/select_eval2.py > attacksim/eval2_candidates.tsv
"""
import glob
import os
import random
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RISK = re.compile(r"rm\s+-rf\s+/|log erase|/var/log|csrutil|nvram|kextload|spctl --master-disable|launchctl unload|"
                  r"\bkill\b|pkill|shutdown|reboot|halt|dscl .* -create|sysadminctl|passwd|dd if=|curl|wget|https?://|"
                  r"\bnc\b|ncat|\bssh\b|\bscp\b|\bftp\b|read -p|sudo -S|password", re.I)


def used_tests():
    used = {}
    for line in open(os.path.join(ROOT, "attacksim", "plan.txt"), encoding="utf-8"):
        p = line.split("#")[0].split()
        if len(p) >= 3 and p[1] in ("dev", "eval"):          # เฉพาะชุดของ v1 (ไม่นับ eval2 ที่เลือกจากสคริปต์นี้)
            used.setdefault(p[0], set()).update(int(x.rstrip("!")) for x in p[2].split(","))
    return used


def main():
    used = used_tests()
    pop = []
    for f in sorted(glob.glob(os.path.expanduser("~/AtomicRedTeam/atomics/T*/T*.yaml"))):
        d = yaml.safe_load(open(f, encoding="utf-8"))
        tech = d["attack_technique"]
        for i, t in enumerate(d.get("atomic_tests", []), 1):
            ex = t.get("executor", {})
            cmd = ex.get("command") or ""
            if ("macos" not in t.get("supported_platforms", []) or i in used.get(tech, set())
                    or ex.get("name") not in ("sh", "bash") or RISK.search(cmd)):
                continue
            pop.append((tech, i, "root" if ex.get("elevation_required") else "user", t["name"]))
    random.Random(2570).shuffle(pop)
    print("order\ttechnique\ttest\tprivilege\tname")
    for k, (tech, i, priv, name) in enumerate(pop, 1):
        print(f"{k}\t{tech}\t{i}\t{priv}\t{name}")


if __name__ == "__main__":
    main()
