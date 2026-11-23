"""
Store — เก็บ event และ alert ลง SQLite (ไฟล์ data/detect.db)

เปรียบเหมือน "สมุดบันทึกเหตุการณ์" ปิดโปรแกรมแล้วข้อมูลยังอยู่
ทำให้: (1) ย้อนดูได้ (forensics) (2) รันกฎซ้ำกับ event เดิมได้
(3) วัด latency จาก ts_event กับ ts_alert (4) แยก Visibility Gap ได้

ตาราง:
    events  — ทุก event ที่ normalize แล้ว
    alerts  — event ที่ตรงกฎ (1 แถวต่อ 1 กฎที่จับได้)
"""
import os
import sqlite3

EVENT_FIELDS = [
    "ts_event", "ts_ingest", "event_type", "pid", "ppid", "Image", "ParentImage",
    "CommandLine", "TargetFilename", "SourceFilename", "SigningId", "User",
    # v2
    "TeamId", "SignatureType", "ParentSigningId", "ExtAttr", "Flags", "FileSize", "ItemType", "ItemExecutable", "Seq",
]
V2_COLUMNS = {"TeamId": "TEXT", "SignatureType": "TEXT", "ParentSigningId": "TEXT", "ExtAttr": "TEXT",
              "Flags": "TEXT", "FileSize": "INTEGER", "ItemType": "TEXT", "ItemExecutable": "TEXT", "Seq": "INTEGER"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_event       TEXT,     -- เวลาที่เหตุการณ์เกิด (จาก eslogger, UTC)
    ts_ingest      TEXT,     -- เวลาที่ระบบเรารับเข้ามา (UTC)
    event_type     TEXT,     -- exec / fork / create / rename / unlink
    pid            INTEGER,
    ppid           INTEGER,
    Image          TEXT,
    ParentImage    TEXT,
    CommandLine    TEXT,
    TargetFilename TEXT,
    SourceFilename TEXT,
    SigningId      TEXT,
    User           INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id  INTEGER REFERENCES events(id),
    rule_id   TEXT,     -- เช่น MD-0001
    title     TEXT,
    level     TEXT,     -- low / medium / high / critical
    tactic    TEXT,
    technique TEXT,     -- เช่น T1555.001
    plain_th  TEXT,     -- คำอธิบายภาษาคน
    ts_event  TEXT,
    ts_alert  TEXT      -- เวลาที่ออก alert (ใช้วัด latency)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_event);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_alert);
-- ให้ Dashboard หาโปรเซสแม่ (process tree) จาก pid ได้ทันที ไม่ต้องอ่านทั้งตาราง
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid, id);
-- v2: สถานะของ sensor ทุก 60 วินาที (heartbeat) + จำนวน event ที่หล่น (ช่องว่างของ global_seq_num)
CREATE TABLE IF NOT EXISTS health (
    ts         TEXT,     -- เวลาที่บันทึก (UTC)
    events     INTEGER,  -- event ที่รับในช่วงนี้ (ก่อนกรอง)
    stored     INTEGER,  -- event ที่เก็บลงตาราง events
    dropped    INTEGER,  -- event ที่ Endpoint Security ส่งไม่ถึง (นับจากเลขลำดับที่ขาด)
    pruned     INTEGER   -- event ที่ retention ลบ
);
"""


def connect(path):
    """เปิดฐานข้อมูล (สร้างโฟลเดอร์และตารางให้ถ้ายังไม่มี)"""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    # isolation_level=None = autocommit: บันทึกทันทีทุกแถว ไม่ถือสิทธิ์เขียนค้างไว้ระหว่างรอ event ถัดไป
    db = sqlite3.connect(path, isolation_level=None, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")      # ให้ Dashboard อ่านได้ระหว่างที่ collector เขียน
    db.execute("PRAGMA synchronous=NORMAL")    # เร็วพอสำหรับ autocommit ใน WAL
    db.executescript(SCHEMA)
    have = {r[1] for r in db.execute("PRAGMA table_info(events)")}
    for col, typ in V2_COLUMNS.items():          # ฐานข้อมูลเดิม (v1) เพิ่มคอลัมน์ให้ ไม่ลบข้อมูลเก่า
        if col not in have:
            db.execute(f"ALTER TABLE events ADD COLUMN {col} {typ}")
    return db


def insert_health(db, ts, events, stored, dropped, pruned):
    db.execute("INSERT INTO health (ts, events, stored, dropped, pruned) VALUES (?,?,?,?,?)",
               (ts, events, stored, dropped, pruned))


def prune(db, days):
    """v2 retention: ลบ event ที่เก่ากว่า days วัน ยกเว้น event ที่เป็นหลักฐานของ alert  คืนจำนวนที่ลบ
    (SQLite ไม่คืนพื้นที่ให้ระบบเอง แต่จะนำหน้าว่างกลับมาใช้ ไฟล์จึงหยุดโตแทนที่จะเล็กลง)"""
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    cur = db.execute("DELETE FROM events WHERE ts_ingest < ? AND id NOT IN (SELECT event_id FROM alerts)", (cutoff,))
    return cur.rowcount


def insert_event(db, rec):
    cols = ", ".join(EVENT_FIELDS)
    marks = ", ".join("?" for _ in EVENT_FIELDS)
    cur = db.execute(f"INSERT INTO events ({cols}) VALUES ({marks})",
                     [rec.get(f) for f in EVENT_FIELDS])
    return cur.lastrowid


def insert_alert(db, event_id, rule, rec, ts_alert):
    db.execute(
        "INSERT INTO alerts (event_id, rule_id, title, level, tactic, technique,"
        " plain_th, ts_event, ts_alert) VALUES (?,?,?,?,?,?,?,?,?)",
        (event_id, rule.id, rule.title, rule.level, rule.tactic, rule.technique,
         rule.plain_th, rec.get("ts_event"), ts_alert),
    )
