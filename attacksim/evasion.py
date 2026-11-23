"""
Evasion test: ทำพฤติกรรมเดียวกับ test ที่ระบบตรวจจับได้ แต่เปลี่ยนวิธี แล้ววัดว่ายังตรวจจับได้กี่ส่วน
ทุกคำสั่งไม่อันตราย: ทำกับไฟล์ชั่วคราวใน ~/Library/Caches/macdetect-evasion แล้วลบทิ้งตอนจบ
ข้อยกเว้นเดียว: ET-PER-* วาง plist (รัน /usr/bin/true, ไม่โหลด) ใน ~/Library/LaunchAgents แล้วลบทันที
  — macOS อาจแสดงการแจ้งเตือน "Background Items Added"

ชนิดของ variant
  base     = วิธีเดียวกับ Atomic test (ใช้ยืนยันว่ากฎจับได้ภายใต้ชุดทดสอบนี้)
  renamed  = คัดลอกโปรแกรมของระบบไปไว้ชื่ออื่น เซ็นใหม่แบบ ad-hoc แล้วรัน
             (ถ้าไม่เซ็นใหม่ macOS จะฆ่าสำเนาทันทีด้วย launch constraints — พบระหว่างทดสอบ 23 พ.ย.)
  api      = ทำผลลัพธ์เดียวกันผ่าน API ใน Python โดยไม่รันโปรแกรมของระบบ
  alt      = ใช้โปรแกรม/รูปแบบคำสั่งอื่นที่ได้ผลเหมือนกัน
แต่ละ variant ที่ไม่ใช่ base ถูกสุ่ม (seed 2569) เป็นชุด dev (ใช้ออกแบบ v2 ได้) หรือ eval (ห้ามดูตอนออกแบบ v2)

ผล: data/evasion_runs.csv (id, technique, rules, kind, split, version, start_utc, end_utc) → report.py ให้คะแนน
รัน (ต้องเปิด collector ก่อน):  .venv/bin/python attacksim/evasion.py --version v1
"""
import argparse
import csv
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "evasion_runs.csv")
W = os.path.expanduser("~/Library/Caches/macdetect-evasion")
LA = os.path.expanduser("~/Library/LaunchAgents/com.macdetect.evasion.plist")
PY = "/usr/bin/python3"
Q = "com.apple.quarantine"
PLIST = ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
         '"http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key>'
         '<string>com.macdetect.evasion</string><key>ProgramArguments</key><array><string>/usr/bin/true</string>'
         '</array></dict></plist>')


def p(name):
    return os.path.join(W, name)


def sh(cmd):
    return ["/bin/zsh", "-c", cmd]


def quarantined(name):
    def setup():
        open(p(name), "w").write("x")
        subprocess.run(["/usr/bin/xattr", "-w", Q, "0081;00000000;Safari;", p(name)], check=True)
    return setup


def touch(name, text="x"):
    def setup():
        open(p(name), "w").write(text)
    return setup


# (id, technique, rules ที่คาดว่าจะจับใน v1, kind, setup, คำสั่ง)
VARIANTS = [
    ("ET-KC-0", "T1555.001", "MD-0002", "base", None, ["/usr/bin/security", "find-generic-password", "-s", "macdetect-evasion"]),
    ("ET-KC-1", "T1555.001", "MD-0002", "renamed", None, [p("kc"), "find-generic-password", "-s", "macdetect-evasion"]),
    ("ET-KC-2", "T1555.001", "MD-0002", "renamed", None,
     [p("kc-spoof"), "find-generic-password", "-s", "macdetect-evasion"]),

    ("ET-QR-0", "T1553.001", "MD-0017", "base", quarantined("q0"), ["/usr/bin/xattr", "-d", Q, p("q0")]),
    ("ET-QR-1", "T1553.001", "MD-0017", "renamed", quarantined("q1"), [p("xa"), "-d", Q, p("q1")]),
    ("ET-QR-2", "T1553.001", "MD-0017", "api", quarantined("q2"),
     [PY, "-c", f"import ctypes;ctypes.CDLL(None).removexattr(b'{p('q2')}',b'{Q}',0)"]),
    ("ET-QR-3", "T1553.001", "MD-0017", "alt", quarantined("q3"), ["/bin/cp", "-X", p("q3"), p("q3-copy")]),

    ("ET-HD-0", "T1564.001", "MD-0016", "base", touch("h0"), ["/usr/bin/chflags", "hidden", p("h0")]),
    ("ET-HD-1", "T1564.001", "MD-0016", "renamed", touch("h1"), [p("cf"), "hidden", p("h1")]),
    ("ET-HD-2", "T1564.001", "MD-0016", "api", touch("h2"),
     [PY, "-c", f"import os,stat;os.chflags('{p('h2')}',stat.UF_HIDDEN)"]),

    ("ET-B64-0", "T1140", "MD-0019", "base", touch("enc", "aGVsbG8K"), ["/usr/bin/base64", "-d", "-i", p("enc")]),
    ("ET-B64-1", "T1140", "MD-0019", "renamed", touch("enc", "aGVsbG8K"), [p("b6"), "-d", "-i", p("enc")]),
    ("ET-B64-2", "T1140", "MD-0019", "alt", touch("enc", "aGVsbG8K"),
     ["/usr/bin/openssl", "base64", "-d", "-in", p("enc")]),
    ("ET-B64-3", "T1140", "MD-0019", "alt", touch("enc", "aGVsbG8K"),
     ["/usr/bin/perl", "-MMIME::Base64", "-e", f"open F,'{p('enc')}';print decode_base64(<F>)"]),

    ("ET-OSA-0", "T1059.002", "MD-0006", "base", None, ["/usr/bin/osascript", "-e", "return 1"]),
    ("ET-OSA-1", "T1059.002", "MD-0006", "renamed", None, [p("osa"), "-e", "return 1"]),
    ("ET-OSA-2", "T1059.002", "MD-0006", "alt", touch("s.applescript", "return 1"),
     ["/usr/bin/osascript", p("s.applescript")]),

    ("ET-SYS-0", "T1082", "MD-0022", "base", None, ["/usr/bin/sw_vers"]),
    ("ET-SYS-1", "T1082", "MD-0022", "renamed", None, [p("sv")]),
    ("ET-SYS-2", "T1082", "MD-0022", "alt", None, ["/bin/cat", "/System/Library/CoreServices/SystemVersion.plist"]),
    ("ET-SYS-3", "T1082", "MD-0022", "api", None, [PY, "-c", "import platform;platform.mac_ver()"]),

    ("ET-ACC-0", "T1087.001", "MD-0023", "base", None, ["/usr/bin/dscl", ".", "list", "/Users"]),
    ("ET-ACC-1", "T1087.001", "MD-0023", "renamed", None, [p("ds"), ".", "list", "/Users"]),
    ("ET-ACC-2", "T1087.001", "MD-0023", "api", None, [PY, "-c", "import pwd;pwd.getpwall()"]),

    ("ET-NET-0", "T1016", "MD-0025", "base", None, ["/usr/sbin/arp", "-a"]),
    ("ET-NET-1", "T1016", "MD-0025", "renamed", None, [p("ap"), "-a"]),

    ("ET-HIS-0", "T1070.003", "MD-0026", "base", None, sh("unset HISTFILE; true")),
    ("ET-HIS-1", "T1070.003", "MD-0026", "alt", None, sh("HISTFILE=/dev/null; true")),
    ("ET-HIS-2", "T1070.003", "MD-0018", "base", touch(".zsh_history"), ["/bin/rm", p(".zsh_history")]),
    ("ET-HIS-3", "T1070.003", "MD-0018", "alt", touch(".bash_history", "ls\n"), sh(f": > {p('.bash_history')}")),

    ("ET-PRO-0", "T1546.004", "MD-0014", "base", None, sh(f"echo '# macdetect' > {p('home0/.zshrc')}")),
    ("ET-PRO-1", "T1546.004", "MD-0014", "alt", touch("home1/.zshrc", "# existing\n"),
     sh(f"echo '# macdetect' >> {p('home1/.zshrc')}")),

    ("ET-PER-0", "T1543.001", "MD-0011", "base", touch("agent.plist", PLIST), ["/bin/cp", p("agent.plist"), LA]),
    ("ET-PER-1", "T1543.001", "MD-0011", "alt", touch("agent.plist", PLIST), ["/bin/mv", p("agent.plist"), LA]),

    ("ET-SH-0", "T1059.004", "MD-0007", "base", None, ["/bin/sh", "/tmp/macdetect-evasion.sh"]),
    ("ET-SH-1", "T1059.004", "MD-0007", "alt", None, sh("/bin/sh < /tmp/macdetect-evasion.sh")),
    ("ET-SH-2", "T1059.004", "MD-0007", "alt", None, ["/bin/sh", p("x.sh")]),
]

COPIES = {"kc": "/usr/bin/security", "xa": "/usr/bin/xattr", "cf": "/usr/bin/chflags", "b6": "/usr/bin/base64",
          "osa": "/usr/bin/osascript", "sv": "/usr/bin/sw_vers", "ds": "/usr/bin/dscl", "ap": "/usr/sbin/arp"}


def split_of():
    ids = sorted(v[0] for v in VARIANTS if v[3] != "base")
    rnd = random.Random(2569)
    rnd.shuffle(ids)
    half = len(ids) // 2
    return {i: ("dev" if k < half else "eval") for k, i in enumerate(ids)}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def prepare():
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(p("home0"))
    os.makedirs(p("home1"))
    for name, src in COPIES.items():
        shutil.copyfile(src, p(name))          # copy2 จะพยายามคัดลอก flag ของ SIP ด้วยซึ่งทำไม่ได้
        os.chmod(p(name), 0o755)
        # สำเนาโปรแกรมของ Apple ที่ย้ายที่จะถูก launch constraints ฆ่าทันที (exit -9) ผู้โจมตีจึงเซ็นใหม่แบบ ad-hoc
        # kc-spoof ตั้ง identifier ปลอมเป็น com.apple.security เพื่อดูว่ากฎที่ใช้ Signing ID อย่างเดียวถูกหลอกได้ไหม
        subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", p(name)], capture_output=True, check=True)
    shutil.copyfile("/usr/bin/security", p("kc-spoof"))
    os.chmod(p("kc-spoof"), 0o755)
    subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", "-i", "com.apple.security", p("kc-spoof")],
                   capture_output=True, check=True)
    open("/tmp/macdetect-evasion.sh", "w").write("echo macdetect\n")
    open(p("x.sh"), "w").write("echo macdetect\n")


def cleanup():
    if os.path.exists(LA):
        os.remove(LA)
    for f in ("/tmp/macdetect-evasion.sh",):
        if os.path.exists(f):
            os.remove(f)
    shutil.rmtree(W, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="v1 หรือ v2 (เวอร์ชันของตัวตรวจจับที่เปิดอยู่)")
    ap.add_argument("--only", help="รันเฉพาะ id ที่ขึ้นต้นด้วยข้อความนี้")
    args = ap.parse_args()
    split = split_of()
    new = not os.path.exists(OUT)
    out = open(OUT, "a", newline="", encoding="utf-8")
    w = csv.writer(out)
    if new:
        w.writerow(["id", "technique", "rules", "kind", "split", "version", "start_utc", "end_utc", "exit"])
    prepare()
    time.sleep(3)
    try:
        for vid, tech, rules, kind, setup, cmd in VARIANTS:
            if args.only and not vid.startswith(args.only):
                continue
            if setup:
                setup()
                time.sleep(2)                      # alert จาก setup ต้องอยู่นอกช่วงเวลาของ variant
            start = now()
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            end = now()
            w.writerow([vid, tech, rules, kind, split.get(vid, "base"), args.version, start, end, r.returncode])
            out.flush()
            print(f"{vid:9} {kind:8} exit {r.returncode}")
            if vid.startswith("ET-PER") and os.path.exists(LA):
                os.remove(LA)
            time.sleep(2)
    finally:
        cleanup()
        out.close()
    print(f"บันทึกช่วงเวลาไว้ที่ {OUT}  → รัน python scripts/report.py เพื่อดูคะแนน")


if __name__ == "__main__":
    sys.exit(main())
