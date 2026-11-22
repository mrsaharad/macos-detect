# รายงานตรวจโค้ด macos-detect (22 พ.ย. 2026)

ตรวจทั้งระบบ: collector → normalize → store → rule engine → Dashboard → report.py
และทดลองกับฐานข้อมูลจริง `data/detect.db` (151,409 event, 16 alert, ช่วง 21–22 พ.ย.)

ผลรวม: ทุกส่วนส่งข้อมูลต่อกันถูกต้อง เทสต์ผ่าน 25/25 กฎ
เจอบั๊ก 2 จุด และจุดที่ควรปรับปรุง 4 จุด แก้ไปแล้ว 4 ข้อ (ข้อ 1–4)

---

## แก้แล้ว

### 1. report.py ไม่นับผลตัดสิน TP/FP จาก Dashboard (บั๊ก)
- **ปัญหา:** Dashboard เก็บผลตัดสินเป็นรหัส `tp` / `fp` (`dashboard/app.py` บรรทัด 46, 73)
  แต่ `scripts/report.py` นับคำว่า `True Positive` / `False Positive` จึงนับได้ 0 เสมอ
  ค่า Precision จากผู้วิเคราะห์จะไม่แสดงในผลบทที่ 4
- **แก้:** `scripts/report.py` นับ `tp` / `fp` ให้ตรงกับ Dashboard
- **ตรวจแล้ว:** ใส่ข้อมูลทดลอง tp 2 แถว + fp 1 แถว → นับได้ TP 2, FP 1 ถูกต้อง

### 2. Dashboard เปิดให้เครื่องอื่นใน Wi-Fi เดียวกันเข้าได้ (บั๊กด้านความปลอดภัย)
- **ปัญหา:** โดยค่าเริ่มต้น Streamlit เปิดรับทุก network ถ้าใช้ Wi-Fi สาธารณะหรือของมหาวิทยาลัย
  คนอื่นจะเห็น command line ทั้งหมดของเครื่อง และกดตัดสิน TP/FP แทนได้
- **แก้:** เพิ่ม `address = "localhost"` ใน `.streamlit/config.toml`
- **ตรวจแล้ว:** Streamlit อ่านค่า `server.address = localhost` ได้

### 3. Process tree ช้าลงตามขนาดข้อมูล (ประสิทธิภาพ)
- **ปัญหา:** หน้า Alerts หาโปรเซสแม่ด้วย `WHERE pid=?` แต่ไม่มี index บน `pid`
  SQLite ต้องอ่านทั้งตาราง ใช้ประมาณ 22 ms ต่อขั้น (ทำสูงสุด 5 ขั้นต่อการเปิด 1 alert) และจะช้าลงเรื่อยๆ ตามจำนวน event
- **แก้:** เพิ่ม `CREATE INDEX idx_events_pid ON events(pid, id)` ใน `collector/store.py`
- **ตรวจแล้ว:** บนสำเนาฐานข้อมูลจริง ลดจาก ~22 ms เหลือ ~0.04 ms ต่อขั้น และ `EXPLAIN QUERY PLAN` ยืนยันว่าใช้ index ใหม่
- **หมายเหตุ:** ฐานข้อมูลเดิมจะได้ index อัตโนมัติเมื่อเปิด collector ครั้งถัดไป

### 4. cache ของ Normalizer เก็บ pid ที่จบไปแล้วไว้ตลอด (หน่วยความจำ)
- **ปัญหา:** `pid_image` ใน `collector/normalize.py` ไม่เคยลบ pid ของโปรเซสที่จบแล้ว
  (ตอนแรกรายงานว่า "แรมโตไม่หยุด" ซึ่งไม่ถูกต้อง เลข pid บน macOS สูงสุด 99,999
  จึงใช้แรมสูงสุดประมาณ 21 MB ตามที่วัด) แต่ยังทำให้ผลวัด RAM ตามวัตถุประสงค์ข้อ 3 สูงกว่าที่ควร
- **แก้:**
  - `collector/normalize.py` — เมื่อเจอ event `exit` ให้ลบ pid นั้นออกจาก cache และไม่เก็บ event นี้ลงฐานข้อมูล
  - `start_collector.command` และคำอธิบายใน `collector/collector.py` — เพิ่ม `exit` ในคำสั่ง eslogger:
    `sudo eslogger exec fork exit create rename unlink | python collector/collector.py`
  - `tests/test_rules.py` — เพิ่มเทสต์ว่า exit ลบ pid ที่ถูกต้องออก และไม่ลบโปรเซสแม่
- **ตรวจแล้ว:** `python tests/test_rules.py` ผ่านทั้งหมด (กฎ 25 ข้อ ผิด 0 + เทสต์ ParentImage + เทสต์ exit)
- **ยังไม่ได้ตรวจ:** การรันสดกับ eslogger จริงหลังเพิ่ม `exit` (โครงสร้าง event อ้างอิงจากเอกสาร Endpoint Security)

---

## ยังไม่ได้แก้ (แนะนำ)

### 5. run_atomic.sh ไม่เก็บผลลัพธ์ของแต่ละ test — แก้แล้ว (อัปเดตหลังติดตั้ง Atomic Red Team)
- **ปัญหาเดิม:** ผลจาก `Invoke-AtomicTest` แสดงแค่บนจอ ถ้า test ล้มเหลวก็ยังบันทึกช่วงเวลาลง `runs.csv`
  สถานะ `Not-Visible?` จึงแยกไม่ออกว่า "ระบบมองไม่เห็น" หรือ "test ไม่ได้รันจริง"
- **ปัญหาที่เจอเพิ่มหลังติดตั้ง:** สคริปต์รัน `pwsh -NoProfile` ซึ่งไม่โหลด module ให้ จึงหาคำสั่ง
  `Invoke-AtomicTest` ไม่เจอ ถ้ารันแผนตอนนั้น ทุก test จะล้มเหลวโดยไม่มีอะไรบอก แต่ยังจดเวลาลง `runs.csv`
- **แก้:** `attacksim/run_atomic.sh` โหลด module จาก `~/AtomicRedTeam/invoke-atomicredteam/` เอง
  (หยุดพร้อมข้อความถ้าไม่พบ) และเก็บผล prereqs / run / cleanup ไว้ที่ `data/atomic_logs/<technique>.log`
- **ตรวจแล้ว:** syntax ผ่าน และฟังก์ชันที่ใช้โหลด module แสดงรายการ test ของ T1082 ได้ (ตรวจแบบไม่รัน test จริง)

### 6. Dashboard ดึงฟอนต์จาก Google Fonts โดยไม่จำเป็น
`dashboard/app.py` บรรทัด 230 มี `@import` ไปที่ fonts.googleapis.com ทั้งที่มีไฟล์ Sarabun อยู่ใน `dashboard/static/fonts/` แล้ว
ลบบรรทัดนี้ได้ (ไม่ต้องต่อเน็ต และไม่มี event เครือข่ายเกินมาจากตัว Dashboard เอง)

### 7. ยังไม่ได้ commit งาน
งานทั้งหมดตั้งแต่ `collector v0` ยังไม่อยู่ใน git ถ้าไฟล์หายจะกู้คืนไม่ได้

---

## ข้อสังเกตสำหรับเล่ม (บทที่ 4 / System Overhead)
- ใน 151,409 event มีประมาณ 92% เป็น create / rename / unlink (139k) ส่วนใหญ่มาจาก daemon ของระบบ
  เช่น `com.apple.WebKit.Networking`, `cfprefsd`, `mobileassetd` แต่มีกฎแค่ 4 ข้อที่ใช้ event ชนิดนี้
- ฐานข้อมูลโตเป็น 64 MB ในเวลาประมาณ 14 ชั่วโมง ใช้เป็นข้อมูลด้านพื้นที่จัดเก็บได้
- ค่าแรมสูงสุดของ cache ก่อนแก้ข้อ 4 ประมาณ 21 MB (วัดด้วย tracemalloc กับ 99,999 pid)

## ต้องทำหลังจากนี้
1. ปิดและเปิด collector ใหม่ (ให้ได้คำสั่ง eslogger ที่มี `exit` และสร้าง index)
2. ปิดและเปิด Dashboard ใหม่ (ให้ได้ค่า `address = localhost`) แล้วเข้าที่ http://localhost:8501
3. commit งานเข้า git

## ไฟล์ที่แก้
| ไฟล์ | การเปลี่ยนแปลง |
|---|---|
| `scripts/report.py` | นับ `tp` / `fp` |
| `.streamlit/config.toml` | `address = "localhost"` |
| `collector/store.py` | index `idx_events_pid` |
| `collector/normalize.py` | จัดการ event `exit` |
| `collector/collector.py` | คำอธิบายคำสั่ง eslogger เพิ่ม `exit` |
| `start_collector.command` | คำสั่ง eslogger เพิ่ม `exit` |
| `tests/test_rules.py` | เทสต์ exit |
