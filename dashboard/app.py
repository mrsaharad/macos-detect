"""
Dashboard — macOS Detect console (Streamlit)

หน้าตาทำตาม mockup ใน Claude Design ("macOS Detect Dashboard")
วิธีทำ: Streamlit อ่านฐานข้อมูลและรีเฟรช ส่วนหน้าตาทั้งหมดเป็น HTML ที่เราสร้างเอง (st.html)
  - ปุ่ม/เมนู/แถวตาราง = ลิงก์ที่เปลี่ยน query string เช่น ?page=alerts&id=12
  - ช่องค้นหา = <form method="get"> ธรรมดา
  - Streamlit อ่านค่าจาก st.query_params แล้ววาดหน้าใหม่
อ่านจาก data/detect.db แบบอ่านอย่างเดียว ผลตัดสิน TP/FP เก็บแยกใน data/verdicts.db

หน้า:  overview (ภาพรวม) | alerts (รายการ + รายละเอียด) | events (ค้นหาเหตุการณ์) | rules (กฎและ ATT&CK)
รัน:   streamlit run dashboard/app.py
"""
import glob
import html
import os
import platform
import plistlib
import re
import socket
import sqlite3
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from urllib.parse import parse_qsl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from engine.rules import load_rules   # noqa: E402

DB = os.environ.get("DETECT_DB", os.path.join(ROOT, "data", "detect.db"))
VDB = os.path.join(os.path.dirname(DB), "verdicts.db")   # ผลตัดสินแยกไฟล์ ไม่แย่งสิทธิ์เขียนกับ collector
TZ = "Asia/Bangkok"

SEV = {"critical": ("Critical", "#f2555a"), "high": ("High", "#f08c3c"),
       "medium": ("Medium", "#d6b23b"), "low": ("Low", "#6d9bd8")}
SEV_ORDER = list(SEV)
TACTICS = [("discovery", "Discovery"), ("execution", "Execution"), ("persistence", "Persistence"),
           ("credential_access", "Credential Access"), ("stealth", "Stealth"),
           ("defense_impairment", "Defense Impairment")]
TACTIC_NAME = dict(TACTICS)
VERDICT = {"tp": ("True positive", "#e9a4a6"), "fp": ("False positive", "#9fc3a9")}
RANGES = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440}

st.set_page_config(page_title="macOS Detect", page_icon=":material/shield:", layout="wide",
                   initial_sidebar_state="collapsed")


# ================================================================ ข้อมูล
def connect():
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)
    db.execute("ATTACH DATABASE ? AS v", (f"file:{VDB}?mode=ro",))
    return db


def q(sql, params=()):
    with connect() as db:
        return pd.read_sql_query(sql, db, params=params)


def init_verdicts():
    with sqlite3.connect(VDB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS alert_verdicts (alert_id INTEGER PRIMARY KEY, verdict TEXT, note TEXT, ts TEXT)")


def set_verdict(alert_id, verdict):
    with sqlite3.connect(VDB) as db:
        if verdict in VERDICT:
            db.execute("INSERT OR REPLACE INTO alert_verdicts VALUES (?,?,?,?)",
                       (alert_id, verdict, "", datetime.now(timezone.utc).isoformat()))
        else:
            db.execute("DELETE FROM alert_verdicts WHERE alert_id=?", (alert_id,))


@st.cache_data(show_spinner=False)
def rules_meta():
    """ข้อมูลกฎจากไฟล์ YAML (ชื่อและคำอธิบายภาษาอังกฤษ) — ใช้แทนข้อความที่เก็บตอนออก alert"""
    return {r.id: dict(title=r.title, desc=r.description, level=r.level, tactic=r.tactic, technique=r.technique)
            for r in load_rules(os.path.join(ROOT, "rules"))}


@st.cache_data(show_spinner=False)
def machine():
    """ชื่อเครื่องและเวอร์ชัน macOS สำหรับมุมล่างซ้าย
    อ่านจากไฟล์ plist ของระบบโดยตรง ไม่รันคำสั่ง (เช่น sw_vers) เพราะระบบตรวจจับจะจับ Dashboard เองเป็น alert"""
    def plist(path, key):
        try:
            with open(path, "rb") as f:
                return plistlib.load(f).get(key, "")
        except Exception:
            return ""
    ver = plist("/System/Library/CoreServices/SystemVersion.plist", "ProductVersion")
    build = plist("/System/Library/CoreServices/SystemVersion.plist", "ProductBuildVersion")
    try:
        with open("/Library/Preferences/SystemConfiguration/preferences.plist", "rb") as f:
            name = plistlib.load(f)["System"]["System"]["ComputerName"]
    except Exception:
        name = socket.gethostname()
    os_line = f"macOS {ver}" + (f" ({build})" if build else "") if ver else platform.system()
    return name, os_line


def parse_ts(series):
    s = series.astype(str).str.replace(r"(\.\d{6})\d+", r"\1", regex=True)
    return pd.to_datetime(s, utc=True, format="ISO8601")


def load_alerts():
    df = q("""SELECT a.id, a.ts_event, a.ts_alert, a.rule_id, a.event_id, e.event_type, e.pid, e.ppid,
                     e.Image, e.ParentImage, e.CommandLine, e.TargetFilename, e.SourceFilename, e.SigningId, e.User,
                     vd.verdict
              FROM alerts a JOIN events e ON e.id = a.event_id
              LEFT JOIN v.alert_verdicts vd ON vd.alert_id = a.id
              ORDER BY a.ts_event DESC, a.id DESC""")
    if not len(df):
        return df
    df = df.astype(object).where(pd.notna(df), None)
    meta = rules_meta()
    for col in ("title", "desc", "level", "tactic", "technique"):
        df[col] = df["rule_id"].map(lambda r, c=col: meta.get(r, {}).get(c, ""))
    df["t"] = parse_ts(df["ts_event"])
    df["latency"] = ((parse_ts(df["ts_alert"]) - df["t"]).dt.total_seconds() * 1000).astype(float)
    return df


def process_chain(r, depth=5):
    """ไล่หาโปรเซสแม่ย้อนขึ้นไปจากตาราง events"""
    chain = [(r["pid"], r["Image"])]
    ppid, pimg, ev = r["ppid"], r["ParentImage"], r["event_id"]
    with connect() as db:
        for _ in range(depth):
            if ppid is None:
                break
            chain.append((int(ppid), pimg or "(started before monitoring)"))
            row = db.execute("SELECT ppid, ParentImage FROM events WHERE pid=? AND id<=? AND event_type IN ('exec','fork')"
                             " ORDER BY id DESC LIMIT 1", (int(ppid), int(ev))).fetchone()
            if not row or row[0] in (None, ppid):
                break
            ppid, pimg = row
    return list(reversed(chain))


# ================================================================ ตัวช่วย HTML
def e(s):
    return html.escape("" if s is None else str(s))


def link(**changes):
    """สร้าง URL ใหม่จาก query string ปัจจุบัน (ค่า None = ลบ key นั้น)"""
    p = {k: st.query_params[k] for k in st.query_params}
    p.pop("verdict", None)
    for k, val in changes.items():
        if val is None:
            p.pop(k, None)
        else:
            p[k] = val
    return "?" + urlencode(p)


def local(t, fmt="%H:%M:%S"):
    return pd.Timestamp(t).tz_convert(TZ).strftime(fmt)


def pill(level):
    name, c = SEV.get(level, (level, "#949bab"))
    return f'<span class="pill" style="color:{c};background:{c}22">{name}</span>'


def basename(p):
    if not isinstance(p, str) or not p:      # ค่าว่างจากฐานข้อมูลอาจมาเป็น None หรือ NaN
        return ""
    return os.path.basename(p) or p


# ไอคอนเส้น: Streamlit ตัด <svg> ออกจาก st.html จึงวาดผ่าน CSS mask (สีตามตัวหนังสือ)
ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/>'
                '<rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    "alerts": '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17.5v.5"/>',
    "events": '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    "rules": '<path d="M5 4h11l3 3v13H5z"/><path d="M8.5 10h7M8.5 13.5h7M8.5 17h4"/>',
    "refresh": '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3z"/><path d="M8.5 12.5l2.3 2.3 4.7-5"/>',
}


def icon_css():
    from urllib.parse import quote
    out = []
    for name, body in ICONS.items():
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" '
               f'stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round">{body}</svg>')
        uri = "url(\"data:image/svg+xml," + quote(svg) + "\")"
        out.append(f".i-{name}{{-webkit-mask:{uri} center/contain no-repeat;mask:{uri} center/contain no-repeat}}")
    return "\n".join(out)


def icon(name, size=18):
    return f'<i class="ico i-{name}" style="width:{size}px;height:{size}px" aria-hidden="true"></i>'


# ================================================================ CSS (ตาม mockup)
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "fonts")
WEIGHT_WORDS = {"thin": 100, "extralight": 200, "light": 300, "regular": 400, "medium": 500,
                "semibold": 600, "bold": 700, "extrabold": 800, "black": 900}


def font_faces():
    """@font-face จากไฟล์ใน dashboard/static/fonts (ชื่อไฟล์ที่มีคำว่า mono = ฟอนต์โค้ด)"""
    out = []
    for path in sorted(glob.glob(os.path.join(FONT_DIR, "*"))):
        name = os.path.basename(path)
        stem, _, ext = name.rpartition(".")
        if ext.lower() not in ("ttf", "otf", "woff", "woff2") or "italic" in stem.lower():
            continue
        fmt = {"ttf": "truetype", "otf": "opentype", "woff": "woff", "woff2": "woff2"}[ext.lower()]
        fam = "UIMono" if "mono" in stem.lower() else "UIFont"
        parts = [x.lower() for x in re.split(r"[-_. ]+", stem)]
        w = next((WEIGHT_WORDS[x] for x in reversed(parts) if x in WEIGHT_WORDS), 400)
        out.append(f"@font-face{{font-family:'{fam}';src:url('/app/static/fonts/{name}') format('{fmt}');"
                   f"font-weight:{w};font-display:swap}}")
    return "\n".join(out)


CSS = """
@import url('https://fonts.googleapis.com/css2?family=Sarabun:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
%FONTS%
:root{--bg:#171a21;--side:#13161c;--panel:#1e222b;--line:#2b303b;--line2:#262b35;--text:#e6e8ec;--muted:#949bab;
  --soft:#a3aab8;--accent:#a594f9;--link:#c9c0ff;--ui:'UIFont','Sarabun',-apple-system,sans-serif;
  --mono:'UIMono','JetBrains Mono',ui-monospace,monospace}
/* ปิดส่วนประกอบของ Streamlit ที่ไม่ใช้ */
header[data-testid="stHeader"],[data-testid="stSidebar"],[data-testid="stSidebarCollapsedControl"],
[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stStatusWidget"],footer{display:none!important}
.stApp{background:var(--bg)}
[data-testid="stMainBlockContainer"],.block-container{padding:0!important;max-width:none!important}
[data-testid="stVerticalBlock"]{gap:0!important}
[data-testid="stElementContainer"]{margin:0!important}
.stHtml,.stHtml *{box-sizing:border-box}

.app{display:flex;flex-wrap:wrap;min-height:var(--vh,100vh);font-family:var(--ui);color:var(--text);background:var(--bg);font-size:15px;line-height:1.5}
.app a{color:var(--link);text-decoration:none}.app a:hover{color:#e2dcff}
.mono{font-family:var(--mono)}
.ico{display:inline-block;flex:none;background:currentColor}
.num{font-variant-numeric:tabular-nums}

/* แถบซ้าย */
.side{flex:1 1 220px;max-width:100%;padding:28px 16px;background:var(--side);border-right:1px solid var(--line2);display:flex;flex-direction:column;gap:28px}
.brand{padding:0 12px;display:flex;align-items:center;gap:10px}
.brand b{display:block;font-size:16px;letter-spacing:-.1px}
.brand span{display:block;font-size:13px;color:var(--muted)}
.nav{display:flex;flex-direction:column;gap:2px}
.app .nav a{display:flex;align-items:center;gap:10px;height:40px;padding:0 12px;border-radius:6px;color:var(--soft);font-size:15px}
.app .nav a:hover{background:#1f232c;color:var(--text)}
.app .nav a.on{background:#222632;color:#f1f2f5;font-weight:600;box-shadow:inset 2px 0 0 var(--accent)}
.badge{margin-left:auto;font-size:12px;font-weight:600;background:#3a2f5c;color:#d9d2ff;border-radius:10px;padding:0 8px;line-height:20px}
.status{margin-top:auto;padding:14px 12px 0;border-top:1px solid var(--line2);font-size:13px;color:var(--muted);display:flex;flex-direction:column;gap:4px}
.status b{display:flex;align-items:center;gap:8px;color:var(--text);font-size:14px}
.dot{width:8px;height:8px;border-radius:50%}

/* เนื้อหา */
.main{flex:999 1 560px;min-width:0;padding:32px 40px 48px}
.wrap{max-width:1120px;margin:0 auto;display:flex;flex-direction:column;gap:24px}
.head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:16px}
.head h1{margin:0;font-size:28px;font-weight:700;letter-spacing:-.3px;line-height:1.25;color:var(--text)}
.head p{margin:2px 0 0;color:var(--muted);font-size:14px}
.seg{display:flex;gap:2px;padding:3px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.app .seg a{height:32px;line-height:32px;padding:0 14px;color:var(--soft);font-weight:500;font-size:14px;border-radius:5px}
.app .seg a:hover{color:var(--text)}
.app .seg a.on{background:#2c3140;color:#f1f2f5}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}
.ph{display:flex;align-items:baseline;justify-content:space-between;gap:12px}
.ph h2{margin:0;font-size:17px;font-weight:600;color:var(--text)}
.ph span{font-size:13px;color:var(--muted)}

.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}
.stats>div{padding:20px 24px}
.stats>div+div{border-left:1px solid var(--line)}
.stats .l{color:var(--muted);font-size:14px}
.stats .v{font-size:34px;font-weight:700;line-height:1.2}
.stats .v small{font-size:16px;font-weight:500;color:var(--muted);margin-left:4px}
.stats .s{margin-top:8px;font-size:13px;color:var(--soft);display:flex;flex-wrap:wrap;gap:4px 14px}
.sq{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}

.lanes{display:grid;grid-template-columns:64px minmax(0,1fr)}
.lanes .n{height:40px;display:flex;align-items:center;font-size:13px;color:var(--soft)}
.lanes .lane{position:relative;height:40px;border-bottom:1px solid var(--line2)}
.lanes .tick{position:absolute;top:9px;width:3px;height:22px;border-radius:2px;margin-left:-1px}
.axis{display:flex;justify-content:space-between;padding-top:8px;font-size:12px;color:var(--muted)}

.cols{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start}
table.t{width:100%;border-collapse:collapse;font-size:14px}
.t th{font-weight:500;color:var(--muted);font-size:13px;text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}
.t td{padding:7px 12px;border-bottom:1px solid var(--line2);vertical-align:middle;line-height:1.4}
.t th:first-child,.t td:first-child{padding-left:20px}
.t th:last-child,.t td:last-child{padding-right:20px}
.t tr:last-child td{border-bottom:none}
.t .tm{color:var(--soft);white-space:nowrap}
.t .sub{font-family:var(--mono);font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:420px}
.rowlink td{cursor:pointer}
.rowlink:hover td{background:#232833}
.rowlink.on td{background:#262a3a}
.rowlink.on td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
.app a.cover{color:inherit;display:block}
.pill{display:inline-block;min-width:58px;text-align:center;font-size:12px;font-weight:600;line-height:22px;border-radius:4px}
.scroll{overflow-x:auto}

.tac{padding:10px 0;border-top:1px solid var(--line2)}
.tac .r{display:flex;justify-content:space-between;gap:12px;font-size:14px}
.tac .r small{color:var(--muted);font-size:12px;margin-left:6px}
.bar{height:4px;margin-top:8px;background:#2a2f3a;border-radius:2px}
.bar i{display:block;height:4px;border-radius:2px;background:var(--accent)}

.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.search{position:relative;flex:1 1 260px;max-width:340px;margin:0}
.search .ico{position:absolute;left:11px;top:8px;color:#7d8494}
.search input{width:100%;height:32px;padding:0 12px 0 34px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:400 14px var(--ui);outline:none}
.search input:focus{border-color:#5b5294}
.search input::placeholder{color:#7d8494}
.app a.chip{height:32px;padding:0 12px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--text);font-weight:500;font-size:14px;display:inline-flex;align-items:center;gap:8px}
.app a.chip:hover{border-color:#3a4050}
.app a.chip.off{background:transparent;border-style:dashed;color:#8a91a1}
.app a.chip.sel{border-color:#5b5294;background:#2a2640}
.sp{flex:1}

.detail>div{padding:18px 24px;border-bottom:1px solid var(--line)}
.detail>div:last-child{border-bottom:none}
.detail h2{margin:0;font-size:21px;font-weight:700;line-height:1.4;color:var(--text)}
.detail h3{margin:0 0 10px;font-size:15px;font-weight:600;color:var(--text)}
.detail .why{margin:8px 0 0;font-size:14px;color:#b5bbc7}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px;font-size:13px}
.tags span{padding:2px 8px;border-radius:4px;background:#262b36;color:#c3c8d3}
.tree div{padding:3px 0;font-size:13px;font-family:var(--mono);color:#c3c8d3}
.tree .pid{font-size:12px;color:var(--muted);margin-left:8px}
.tree .hit{color:#f1f2f5;font-weight:500;background:#3a2530;padding:1px 6px;border-radius:4px}
.tree .br{color:#5f6676;margin-right:6px}
dl.kv{padding:0!important;display:grid;grid-template-columns:112px minmax(0,1fr);gap:8px 16px;margin:0;font-size:14px}
.kv dt{color:var(--muted);margin:0!important;padding:0!important;font-weight:400}
.kv dd{margin:0!important;padding:0!important;font-family:var(--mono);font-size:13px;word-break:break-all;color:var(--text)}
.vb{display:flex;gap:8px}
.app .vb a{flex:1;height:44px;display:flex;align-items:center;justify-content:center;border-radius:7px;border:1px solid var(--line);background:#1a1d25;color:#c3c8d3;font-weight:500}
.app .vb a:hover{border-color:#3a4050;color:#f1f2f5}
.app .vb a.tp{background:#3a2530;border-color:#7a3c44;color:#f6d4d5}
.app .vb a.fp{background:#203329;border-color:#3d6b4f;color:#d3ecd9}
.empty{padding:40px 24px;text-align:center;color:var(--muted)}

.cov{display:grid;grid-template-columns:repeat(6,minmax(0,1fr))}
.cov>div{padding:16px 14px}
.cov>div+div{border-left:1px solid var(--line)}
.cov b{display:block;font-size:14px}
.cov small{display:block;color:var(--muted);font-size:12px;margin-bottom:10px}
.cell{display:flex;justify-content:space-between;font-family:var(--mono);font-size:12px;padding:5px 8px;border-radius:4px;margin-bottom:4px;background:#262b36;color:var(--soft)}
.cell.hit{background:#3a2530;color:#f6d4d5}
#root.busy{cursor:progress}
#root.busy .main{opacity:.88;transition:opacity .12s .15s}
iframe{display:block}
@media (max-width:900px){.stats,.cov{grid-template-columns:repeat(2,minmax(0,1fr))}.main{padding:24px 16px}}
"""


def page_shell(active, body, open_count, last_age):
    name, os_line = machine()
    on = last_age is not None and last_age < 30
    if last_age is None:
        age = "No events yet"
    elif last_age < 120:
        age = f"Last event {int(last_age)} seconds ago"
    else:
        age = f"Last event {int(last_age // 60)} minutes ago"
    items = [("overview", "Overview", None), ("alerts", "Alerts", open_count), ("events", "Event search", None),
             ("rules", "Rules &amp; ATT&amp;CK", None)]
    nav = "".join(
        f'<a href="?page={k}" target="_self" class="{"on" if k == active else ""}"'
        f'{" aria-current=page" if k == active else ""}>{icon(k)}{label}'
        f'{f"<span class=badge>{badge}</span>" if badge else ""}</a>' for k, label, badge in items)
    return f"""<div class="app">
<aside class="side">
  <div class="brand"><span style="color:#c9c0ff;display:flex">{icon("shield", 22)}</span><div><b>macOS Detect</b><span>{e(name)}</span></div></div>
  <nav class="nav" aria-label="Main">{nav}</nav>
  <div class="status"><b><span class="dot" style="background:{"#3fb97a" if on else "#5d6578"}"></span>
    {"Monitoring" if on else "Collector stopped"}</b><div>{age}</div><div>{e(os_line)}</div></div>
</aside>
<main class="main"><div class="wrap">{body}</div></main>
</div>"""


def last_event_age():
    t = q("SELECT MAX(ts_ingest) t FROM events")["t"][0]
    if not t:
        return None
    return (datetime.now(timezone.utc) - parse_ts(pd.Series([t]))[0]).total_seconds()


# ================================================================ หน้า: Overview
def overview_body(a, rng):
    now = pd.Timestamp.now(tz="UTC")
    n_events = int(q("SELECT COUNT(*) n FROM events")["n"][0])
    rate = int(q("SELECT COUNT(*) n FROM events WHERE ts_ingest >= ?",
                 ((now - pd.Timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S"),))["n"][0])
    counts = a["level"].value_counts() if len(a) else pd.Series(dtype=int)
    reviewed = int(a["verdict"].notna().sum()) if len(a) else 0
    sev_line = "".join(f'<span><span class="sq" style="background:{SEV[s][1]}"></span>{SEV[s][0]} '
                       f'{int(counts.get(s, 0))}</span>' for s in SEV_ORDER)
    if len(a):
        lat = f'{a["latency"].median():,.0f}<small>ms</small>'
        lat_sub = f'Median. Slowest {a["latency"].max():,.0f} ms'
    else:
        lat, lat_sub = "–", "No alerts yet"

    seg = "".join(f'<a href="{link(range=k)}" target="_self" class="{"on" if k == rng else ""}">{k}</a>'
                  for k in RANGES)
    head = (f'<header class="head"><div><h1>Overview</h1><p>Refreshes every 3 seconds. Last update '
            f'{now.tz_convert(TZ).strftime("%H:%M:%S")}</p></div>'
            f'<nav class="seg" aria-label="Time range">{seg}</nav></header>')

    stats = f"""<section class="panel stats num" aria-label="Summary">
      <div><div class="l">Alerts</div><div class="v">{len(a):,}</div><div class="s">{sev_line}</div></div>
      <div><div class="l">Awaiting review</div><div class="v">{len(a) - reviewed:,}</div><div class="s">{reviewed:,} reviewed</div></div>
      <div><div class="l">Events collected</div><div class="v">{n_events:,}</div><div class="s">{rate:,} per minute now</div></div>
      <div><div class="l">Detection latency</div><div class="v">{lat}</div><div class="s">{lat_sub}</div></div>
    </section>"""

    # แถบเหตุการณ์ 4 เลน: ตำแหน่งขีด = สัดส่วนเวลาในช่วงที่เลือก
    minutes = RANGES[rng]
    start = now - pd.Timedelta(minutes=minutes)
    win = a[a["t"] >= start] if len(a) else a
    lanes = ""
    for s in SEV_ORDER:
        ticks = ""
        if len(win):
            for _, r in win[win["level"] == s].iterrows():
                left = (r["t"] - start).total_seconds() / (minutes * 60) * 100
                ticks += (f'<span class="tick" title="{local(r["t"])} {e(r["title"])}" '
                          f'style="left:{left:.2f}%;background:{SEV[s][1]}"></span>')
        lanes += f'<div class="n">{SEV[s][0]}</div><div class="lane">{ticks}</div>'
    marks = [start + (now - start) * i / 6 for i in range(7)]
    fmt = "%H:%M" if minutes <= 360 else "%d %b %H:%M"
    axis = "".join(f"<span>{local(m, fmt)}</span>" for m in marks[:-1]) + "<span>Now</span>"
    timeline = f"""<section class="panel" style="padding:20px 24px 16px" aria-labelledby="tl">
      <div class="ph" style="margin-bottom:14px"><h2 id="tl">Alerts over time</h2>
      <span>{len(win)} in the last {rng}</span></div>
      <div class="lanes">{lanes}<div></div><div class="axis num">{axis}</div></div></section>"""

    if len(a):
        rows = "".join(
            f'<tr class="rowlink"><td class="tm num"><a class="cover" href="{link(page="alerts", id=int(r["id"]))}" target="_self">'
            f'{local(r["t"])}</a></td><td>{pill(r["level"])}</td><td style="font-weight:500">{e(r["title"])}</td>'
            f'<td class="mono" style="font-size:13px;color:var(--soft);white-space:nowrap">{e(basename(r["Image"]))}</td></tr>'
            for _, r in a.head(7).iterrows())
        table = (f'<div class="scroll"><table class="t" style="min-width:560px"><thead><tr><th style="width:84px">Time</th>'
                 f'<th style="width:84px">Severity</th><th>Detection</th><th style="width:130px">Process</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table></div>')
    else:
        table = '<div class="empty">No alerts yet. The collector is watching this Mac.</div>'
    recent = (f'<section class="panel" style="flex:999 1 520px;min-width:0;overflow:hidden" aria-labelledby="re">'
              f'<div class="ph" style="padding:18px 24px 12px"><h2 id="re">Recent alerts</h2>'
              f'<a href="?page=alerts" target="_self" style="font-size:14px">View all</a></div>{table}</section>')

    meta = pd.DataFrame(rules_meta().values())
    rule_n = meta["tactic"].value_counts()
    tcount = a["tactic"].value_counts() if len(a) else pd.Series(dtype=int)
    top = max(int(tcount.max()) if len(tcount) else 0, 1)
    tac = "".join(
        f'<div class="tac"><div class="r"><span>{name}<small>{int(rule_n.get(k, 0))} rules</small></span>'
        f'<span class="num" style="font-weight:600;{"" if tcount.get(k, 0) else "color:var(--muted)"}">{int(tcount.get(k, 0))}</span></div>'
        f'<div class="bar"><i style="width:{tcount.get(k, 0) / top * 100:.0f}%"></i></div></div>'
        for k, name in TACTICS)
    tactics = (f'<section class="panel" style="flex:1 1 300px;min-width:0;padding:18px 24px 10px" aria-labelledby="ta">'
               f'<h2 id="ta" style="margin:0 0 4px;font-size:17px;font-weight:600">Attack stages</h2>'
               f'<p style="margin:0 0 8px;font-size:13px;color:var(--muted)">Grouped by MITRE ATT&amp;CK tactic</p>{tac}</section>')

    return head + stats + timeline + f'<div class="cols">{recent}{tactics}</div>'


# ================================================================ หน้า: Alerts
def alerts_body(a):
    qp = st.query_params
    off = set(filter(None, qp.get("off", "").split(",")))
    status = qp.get("status", "all")
    text = qp.get("q", "").strip()
    view = a
    if len(a):
        view = a[~a["level"].isin(off)]
        if status == "open":
            view = view[view["verdict"].isna()]
        elif status in VERDICT:
            view = view[view["verdict"] == status]
        if text:
            hay = (view["title"].fillna("") + " " + view["Image"].fillna("") + " " + view["CommandLine"].fillna("")
                   + " " + view["TargetFilename"].fillna("") + " " + view["technique"].fillna("") + " " + view["rule_id"])
            view = view[hay.str.contains(re.escape(text), case=False)]
    open_n = int(a["verdict"].isna().sum()) if len(a) else 0
    head = (f'<header class="head"><div><h1>Alerts</h1><p>{len(a):,} alerts, {open_n:,} awaiting review</p></div></header>')

    chips = ""
    for s in SEV_ORDER:
        nxt = off ^ {s}
        chips += (f'<a class="chip {"off" if s in off else ""}" target="_self" href="{link(off=",".join(sorted(nxt)) or None, id=None)}" '
                  f'aria-pressed="{"false" if s in off else "true"}"><span class="sq" style="background:{SEV[s][1]};margin:0"></span>{SEV[s][0]}</a>')
    stat_chips = "".join(
        f'<a class="chip {"sel" if status == k else ""}" target="_self" href="{link(status=None if k == "all" else k, id=None)}">{lbl}</a>'
        for k, lbl in [("all", "All"), ("open", "Open"), ("tp", "True positive"), ("fp", "False positive")])
    hidden = "".join(f'<input type="hidden" name="{k}" value="{e(qp[k])}">' for k in ("page", "off", "status") if qp.get(k))
    if "page" not in qp:
        hidden += '<input type="hidden" name="page" value="alerts">'
    filters = (f'<div class="filters"><form class="search" method="get" role="search">{hidden}'
               f'<label><span style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)">Search alerts</span>'
               f'{icon("events", 16)}<input type="search" name="q" value="{e(text)}" '
               f'placeholder="Search detections, processes, techniques"></label></form>{chips}'
               f'<span class="sp"></span>{stat_chips}</div>')

    if not len(view):
        msg = "No alerts yet. The collector is watching this Mac." if not len(a) else "No alerts match these filters."
        return head + filters + f'<section class="panel"><div class="empty">{msg}</div></section>'

    sel_id = qp.get("id")
    ids = list(view["id"].astype(int))
    sel = int(sel_id) if sel_id and sel_id.isdigit() and int(sel_id) in ids else ids[0]
    rows = ""
    for _, r in view.head(300).iterrows():
        href = link(id=int(r["id"]))
        v = r["verdict"]
        vtxt, vcol = VERDICT[v] if v in VERDICT else ("Open", "var(--muted)")
        sub = r["CommandLine"] or r["TargetFilename"] or r["Image"]
        rows += (f'<tr class="rowlink {"on" if int(r["id"]) == sel else ""}">'
                 f'<td class="tm num"><a class="cover" href="{href}" target="_self">{local(r["t"])}</a></td>'
                 f'<td><a class="cover" href="{href}" target="_self">{pill(r["level"])}</a></td>'
                 f'<td><a class="cover" href="{href}" target="_self"><div style="font-weight:500">{e(r["title"])}</div>'
                 f'<div class="sub">{e(sub)}</div></a></td>'
                 f'<td style="white-space:nowrap;font-size:13px;color:{vcol}"><a class="cover" href="{href}" target="_self">{vtxt}</a></td></tr>')
    more = f'<div class="empty" style="padding:12px">Showing the newest 300 of {len(view):,}</div>' if len(view) > 300 else ""
    listing = (f'<section class="panel" style="flex:999 1 480px;min-width:0;overflow:hidden" aria-label="Alert list">'
               f'<div class="scroll"><table class="t" style="min-width:520px"><thead><tr><th style="width:84px">Time</th>'
               f'<th style="width:84px">Severity</th><th>Detection</th><th style="width:110px">Status</th></tr></thead>'
               f'<tbody>{rows}</tbody></table></div>{more}</section>')

    r = view[view["id"] == sel].iloc[0]
    chain = process_chain(r)
    tree = ""
    for i, (pid, img) in enumerate(chain):
        last = i == len(chain) - 1
        name = e(basename(img))
        tree += (f'<div style="padding-left:{i * 18}px">{"<span class=br>└</span>" if i else ""}'
                 f'<span class="{"hit" if last else ""}">{name}</span><span class="pid">pid {pid}</span></div>')
    user = "root (0)" if r["User"] == 0 else r["User"]
    kv = [("Command", r["CommandLine"] or "-"), ("File", r["TargetFilename"] or "-")]
    if r["SourceFilename"]:
        kv.append(("Renamed from", r["SourceFilename"]))
    kv += [("Process", r["Image"]), ("User", user), ("Signing ID", r["SigningId"] or "-"),
           ("Latency", f'{r["latency"]:,.0f} ms'), ("Event type", r["event_type"])]
    dl = "".join(f"<dt>{k}</dt><dd>{e(val)}</dd>" for k, val in kv)
    cur = r["verdict"]
    vb = "".join(f'<a class="{key if cur == key else ""}" target="_self" href="{link(id=int(r["id"]), verdict="clear" if cur == key else key)}">'
                 f'{VERDICT[key][0]}</a>' for key in ("tp", "fp"))
    detail = f"""<section class="panel detail" style="flex:1 1 380px;min-width:0" aria-label="Details">
      <div style="padding:22px 24px 18px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">{pill(r["level"])}
          <span style="font-size:13px;color:var(--muted)">{local(r["t"], "%b %d, %Y")} at {local(r["t"])}</span></div>
        <h2>{e(r["title"])}</h2><p class="why">{e(r["desc"])}</p>
        <div class="tags"><span>{e(r["rule_id"])}</span><span>{e(r["technique"])}</span>
          <span>{e(TACTIC_NAME.get(r["tactic"], r["tactic"]))}</span></div></div>
      <div><h3>Process tree</h3><div class="tree">{tree}</div></div>
      <div><h3>Evidence</h3><dl class="kv">{dl}</dl></div>
      <div style="padding-bottom:22px"><h3 style="margin-bottom:4px">Analyst verdict</h3>
        <p style="margin:0 0 12px;font-size:13px;color:var(--muted)">Used to calculate detection precision</p>
        <div class="vb">{vb}</div></div>
    </section>"""
    return head + filters + f'<div class="cols" style="gap:20px">{listing}{detail}</div>'


# ================================================================ หน้า: Event search
def events_body():
    qp = st.query_params
    text = qp.get("q", "").strip()
    all_types = ["exec", "fork", "create", "rename", "unlink"]
    types = [t for t in qp.get("types", "exec").split(",") if t in all_types] or ["exec"]
    where = ["event_type IN (%s)" % ",".join("?" * len(types))]
    params = list(types)
    if text:
        where.append("(Image LIKE ? OR CommandLine LIKE ? OR TargetFilename LIKE ? OR ParentImage LIKE ?)")
        params += [f"%{text}%"] * 4
    df = q(f"SELECT ts_event, event_type, pid, ppid, Image, ParentImage, CommandLine, TargetFilename FROM events "
           f"WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT 300", params)
    total = int(q("SELECT COUNT(*) n FROM events")["n"][0])
    head = (f'<header class="head"><div><h1>Event search</h1><p>Every event the collector stored ({total:,} in total). '
            f'Use it to trace activity or find what the rules missed.</p></div>'
            f'<a class="chip" href="{link()}">{icon("refresh", 16)}Refresh</a></header>')
    chips = ""
    for t in all_types:
        nxt = [x for x in all_types if (x in types) != (x == t)]
        chips += (f'<a class="chip {"sel" if t in types else "off"}" target="_self" '
                  f'href="{link(types=",".join(nxt) or "exec")}">{t}</a>')
    hidden = '<input type="hidden" name="page" value="events">' + (
        f'<input type="hidden" name="types" value="{e(",".join(types))}">')
    filters = (f'<div class="filters"><form class="search" method="get" role="search" style="max-width:420px">{hidden}'
               f'<label>{icon("events", 16)}<input type="search" name="q" value="{e(text)}" '
               f'placeholder="Search process, command, or file" aria-label="Search events"></label></form>{chips}</div>')
    if not len(df):
        return head + filters + '<section class="panel"><div class="empty">No events match this search.</div></section>'
    df = df.astype(object).where(pd.notna(df), None)   # NaN -> None
    df["t"] = parse_ts(df["ts_event"])
    rows = "".join(
        f'<tr><td class="tm num">{local(r.t, "%d %b %H:%M:%S")}</td><td class="mono" style="font-size:13px">{e(r.event_type)}</td>'
        f'<td class="mono" style="font-size:13px">{e(basename(r.Image))}<div class="sub">pid {e(r.pid)}</div></td>'
        f'<td class="mono" style="font-size:13px;color:var(--soft)">{e(basename(r.ParentImage) or "-")}<div class="sub">pid {e(r.ppid)}</div></td>'
        f'<td><div class="sub" style="max-width:520px;color:var(--text)">{e(r.CommandLine or r.TargetFilename or r.Image)}</div></td></tr>'
        for r in df.itertuples())
    return head + filters + (
        f'<section class="panel" style="overflow:hidden"><div class="scroll"><table class="t" style="min-width:760px">'
        f'<thead><tr><th style="width:150px">Time</th><th style="width:80px">Type</th><th style="width:170px">Process</th>'
        f'<th style="width:150px">Parent</th><th>Command or file</th></tr></thead><tbody>{rows}</tbody></table></div>'
        f'<div class="empty" style="padding:12px">Showing the newest {len(df):,} matches</div></section>')


# ================================================================ หน้า: Rules & ATT&CK
def rules_body():
    meta = rules_meta()
    hits = dict(q("SELECT rule_id, COUNT(*) n FROM alerts GROUP BY rule_id").values.tolist())
    head = (f'<header class="head"><div><h1>Rules &amp; ATT&amp;CK</h1><p>{len(meta)} rules covering '
            f'{len({m["tactic"] for m in meta.values()})} MITRE ATT&amp;CK tactics</p></div></header>')
    cols = ""
    for k, name in TACTICS:
        rs = [(rid, m) for rid, m in meta.items() if m["tactic"] == k]
        cells = "".join(f'<div class="cell {"hit" if hits.get(rid) else ""}" title="{rid} {e(m["title"])}">'
                        f'<span>{e(m["technique"])}</span><span>{hits.get(rid, "") or ""}</span></div>' for rid, m in rs)
        cols += f'<div><b>{name}</b><small>{len(rs)} rules</small>{cells}</div>'
    cov = (f'<section class="panel" aria-label="Coverage"><div class="cov">{cols}</div></section>'
           f'<p style="margin:-14px 0 0;font-size:13px;color:var(--muted)">Highlighted techniques have fired at least once. '
           f'The number is how many times.</p>')
    rows = "".join(
        f'<tr><td class="mono" style="font-size:13px">{rid}</td><td><div style="font-weight:500">{e(m["title"])}</div>'
        f'<div style="font-size:13px;color:var(--muted)">{e(m["desc"])}</div></td><td>{pill(m["level"])}</td>'
        f'<td style="white-space:nowrap">{e(TACTIC_NAME.get(m["tactic"], m["tactic"]))}</td>'
        f'<td class="mono" style="font-size:13px">{e(m["technique"])}</td>'
        f'<td class="num" style="text-align:right">{hits.get(rid, 0)}</td></tr>'
        for rid, m in meta.items())
    table = (f'<section class="panel" style="overflow:hidden"><div class="scroll"><table class="t" style="min-width:820px">'
             f'<thead><tr><th style="width:96px">Rule</th><th>Detection</th><th style="width:96px">Severity</th>'
             f'<th style="width:150px">Tactic</th><th style="width:100px">Technique</th>'
             f'<th style="width:70px;text-align:right">Fired</th></tr></thead><tbody>{rows}</tbody></table></div></section>')
    return head + cov + table


# ================================================================ เริ่มทำงาน
# console = กรอบ (Streamlit component) ที่แสดงทั้งหน้า คลิกแล้วไม่ต้องโหลดหน้าเว็บใหม่ ดู dashboard/console/index.html
console = components.declare_component("console", path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "console"))
FULL_CSS = f"{CSS.replace('%FONTS%', font_faces())}\n{icon_css()}"
st.html(f"<style>{FULL_CSS}</style>")   # ส่วนของหน้าหลัก: ซ่อนแถบของ Streamlit และตั้งสีพื้น


def show(html_page, key):
    console(html=html_page, css=FULL_CSS, key=key, default=None)


if not os.path.exists(DB):
    show(page_shell("overview", '<header class="head"><div><h1>No data yet</h1><p>Start the collector first '
                    '(double-click start_collector.command), then reload this page.</p></div></header>', None, None), "c_main")
    st.stop()
init_verdicts()


def handle_click():
    """อ่านลิงก์ที่ผู้ใช้คลิกจาก component แล้วเปลี่ยน query string (URL เปลี่ยนแต่หน้าไม่โหลดใหม่)"""
    for key in ("c_main", "c_live"):
        v = st.session_state.get(key)
        if isinstance(v, dict) and v.get("ts") and v["ts"] != st.session_state.get("last_click"):
            st.session_state["last_click"] = v["ts"]
            params = dict(parse_qsl(str(v.get("href", "?"))[1:]))
            verdict = params.pop("verdict", None)
            if verdict and params.get("id", "").isdigit():      # ปุ่ม True/False positive
                set_verdict(int(params["id"]), verdict)
            st.query_params.from_dict(params)
            return True
    return False


def current_page():
    p = st.query_params.get("page", "overview")
    return p if p in ("overview", "alerts", "events", "rules") else "overview"


def render(page, key):
    a = load_alerts()
    open_n = int(a["verdict"].isna().sum()) if len(a) else 0
    if page == "overview":
        rng = st.query_params.get("range", "1h")
        body = overview_body(a, rng if rng in RANGES else "1h")
    elif page == "alerts":
        body = alerts_body(a)
    elif page == "events":
        body = events_body()
    else:
        body = rules_body()
    show(page_shell(page, body, open_n, last_event_age()), key)


@st.fragment(run_every="3s")
def live_overview():
    """หน้าภาพรวมรีเฟรชเองทุก 3 วินาที (เฉพาะส่วนนี้ ไม่ทั้งหน้า)"""
    if handle_click() and current_page() != "overview":
        st.rerun(scope="app")                     # ไปหน้าอื่น: รันทั้งแอปใหม่ จะได้ออกจากโหมดรีเฟรชเอง
    render("overview", "c_live")


handle_click()
if current_page() == "overview":
    live_overview()
else:
    render(current_page(), "c_main")              # หน้าอื่นไม่รีเฟรชเอง เพื่อไม่ให้ช่องค้นหาที่กำลังพิมพ์หาย
