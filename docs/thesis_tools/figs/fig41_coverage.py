"""
รูปที่ 4.1 แผนที่ความครอบคลุมตาม ATT&CK v19 — วาดจากไฟล์ layer เดียวกับที่เปิดใน ATT&CK Navigator
(data/results/navigator_layer.json ซึ่ง scripts/report.py สร้าง) แสดงเฉพาะเทคนิคที่มีกฎหรือถูกทดสอบ
ข้อความในรูปเป็นภาษาอังกฤษ เพราะ Pillow บนเครื่องนี้ไม่มี raqm จึงวางสระ/วรรณยุกต์ไทยไม่ถูก
รัน:  .venv/bin/python docs/thesis_tools/figs/fig41_coverage.py
"""
import json
import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
LAYER = os.path.join(ROOT, "data", "results", "navigator_layer.json")
OUT = os.path.join(os.path.dirname(__file__), "out", "fig41_coverage.png")
FONT = os.path.expanduser("~/Library/Fonts/THSarabunNew.ttf")
FONT_B = os.path.expanduser("~/Library/Fonts/THSarabunNew Bold.ttf")

NAMES = {
    "T1059.002": "AppleScript", "T1059.004": "Unix Shell", "T1059.006": "Python",
    "T1204.002": "Malicious File", "T1569.001": "Launchctl", "T1053.003": "Cron",
    "T1543.001": "Launch Agent", "T1543.004": "Launch Daemon",
    "T1546.004": "Unix Shell Config. Modif.", "T1547.015": "Login Items",
    "T1555.001": "Keychain", "T1056.002": "GUI Input Capture", "T1552.004": "Private Keys",
    "T1016": "System Network Config. Disc.", "T1033": "System Owner/User Discovery",
    "T1057": "Process Discovery", "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery", "T1087.001": "Local Account",
    "T1201": "Password Policy Discovery", "T1217": "Browser Information Discovery",
    "T1518": "Software Discovery", "T1518.001": "Security Software Discovery",
    "T1070.003": "Clear Command History", "T1140": "Deobfuscate/Decode Files",
    "T1553.001": "Gatekeeper Bypass", "T1564.001": "Hidden Files and Directories",
    "T1685": "Disable or Modify Tools", "T1686": "Disable or Modify System Firewall",
    "T1105": "Ingress Tool Transfer",
}
TACTICS = [("execution", "Execution"), ("persistence", "Persistence"),
           ("credential-access", "Credential Access"), ("discovery", "Discovery"),
           ("stealth", "Stealth"), ("defense-impairment", "Defense Impairment"),
           ("command-and-control", "Command and Control")]
LEGEND = [("#5aa469", "Detected in all tests"), ("#f2c94c", "Detected in some tests"),
          ("#f2994a", "Rule exists, missed"), ("#eb5757", "No rule (tested)"),
          ("#9ec5fe", "Rule exists, not tested")]

DPI = 300
W_IN = 5.7
COLS = 3
PX = lambda pt: round(pt * DPI / 72)          # pt -> px ที่ 300 dpi


def main():
    layer = json.load(open(LAYER, encoding="utf-8"))
    by_tac = {k: [] for k, _ in TACTICS}
    for t in layer["techniques"]:
        by_tac.setdefault(t["tactic"], []).append(t)
    for v in by_tac.values():
        v.sort(key=lambda t: t["techniqueID"])
    W = round(W_IN * DPI)
    pad, gap = PX(4), PX(3)
    head_h, cell_h = PX(16), PX(26)
    cell_w = (W - 2 * pad - (COLS - 1) * gap) // COLS
    f_head = ImageFont.truetype(FONT_B, PX(12))
    f_id = ImageFont.truetype(FONT_B, PX(10.5))
    f_name = ImageFont.truetype(FONT, PX(10))
    f_leg = ImageFont.truetype(FONT, PX(10))
    n_rows = sum(-(-len(by_tac[k]) // COLS) for k, _ in TACTICS)
    H = pad + len(TACTICS) * (head_h + gap) + n_rows * (cell_h + gap) + PX(40)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    y = pad
    for key, label in TACTICS:
        items = by_tac.get(key, [])
        d.rectangle([pad, y, W - pad, y + head_h], fill="#e7e6e6")
        d.text((pad + PX(4), y + head_h / 2), f"{label}  ({len(items)} technique{'' if len(items) == 1 else 's'})", font=f_head,
               fill="black", anchor="lm")
        y += head_h + gap
        for j, t in enumerate(items):
            x = pad + (j % COLS) * (cell_w + gap)
            yy = y + (j // COLS) * (cell_h + gap)
            d.rectangle([x, yy, x + cell_w, yy + cell_h], fill=t["color"], outline="#555555", width=2)
            score = f"   {t['score']}%" if "score" in t else ""
            d.text((x + PX(3), yy + PX(1)), t["techniqueID"] + score, font=f_id, fill="black")
            d.text((x + PX(3), yy + PX(13)), NAMES.get(t["techniqueID"], ""), font=f_name, fill="black")
        y += -(-len(items) // COLS) * (cell_h + gap)
    y += PX(6)
    x = pad
    for i, (color, label) in enumerate(LEGEND):
        if i == 3:                                   # ขึ้นบรรทัดใหม่ให้ตำนานไม่ล้นความกว้าง
            x, y = pad, y + PX(16)
        d.rectangle([x, y, x + PX(10), y + PX(10)], fill=color, outline="#555555", width=2)
        d.text((x + PX(14), y + PX(5)), label, font=f_leg, fill="black", anchor="lm")
        x += PX(14) + d.textlength(label, font=f_leg) + PX(14)
    img = img.crop((0, 0, W, y + PX(16)))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, dpi=(DPI, DPI))
    print(OUT, img.size)


if __name__ == "__main__":
    main()
