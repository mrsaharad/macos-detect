"""จับภาพหน้าจอ Dashboard จากข้อมูลจริงของ daemon v2 (หัวข้อ 4.2)
ต้องเปิด Dashboard ไว้ก่อน (พอร์ต 8503):
  DETECT_DB="/Library/Application Support/macdetect/data/detect.db" .venv/bin/streamlit run dashboard/app.py \
      --server.headless true --server.port 8503
รัน: .venv/bin/python docs/thesis_tools/shots/shoot_v2.py  → docs/thesis_tools/shots/out_v2/*.png"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("DASH_URL", "http://localhost:8503/")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out_v2")
SHOTS = {
    "overview_real": "?page=overview&range=24h",
    "incidents_real": "?page=alerts&view=incidents&period=1w",
    "alert_detail_real": f"?page=alerts&period=1w&id={sys.argv[1] if len(sys.argv) > 1 else 59}",
}
os.makedirs(OUT, exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    for name, q in SHOTS.items():
        pg.goto(BASE + q, wait_until="networkidle")
        pg.wait_for_timeout(6000)                          # รอ Streamlit และ component วาดเสร็จ
        frame = pg.frame_locator("iframe").first
        frame.locator("body").wait_for(timeout=20000)
        h = pg.evaluate("() => Math.max(...[...document.querySelectorAll('iframe')].map(f => f.getBoundingClientRect().bottom), 900)")
        pg.set_viewport_size({"width": 1440, "height": int(h) + 40})
        pg.wait_for_timeout(1500)
        pg.screenshot(path=os.path.join(OUT, f"{name}.png"), full_page=True)
        pg.set_viewport_size({"width": 1440, "height": 900})
        print(name, int(h))
    b.close()
