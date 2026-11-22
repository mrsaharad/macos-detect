# macos-detect — ระบบตรวจจับภัยคุกคามบน macOS ด้วยข้อมูลระดับระบบปฏิบัติการ

ระบบตรวจจับและแจ้งเตือน (detection-only) จาก Endpoint Security ผ่าน `eslogger`
เทียบกับกฎ Sigma-style 25 ข้อ (6 tactics ของ MITRE ATT&CK) แสดงผลบน Dashboard

```
eslogger ──► Collector ──► Normalizer ──► SQLite (events) ──► Rule Engine ──► SQLite (alerts) ──► Dashboard
 (กล้อง)     (รปภ.)       (หัวแปลงปลั๊ก)     (สมุดบันทึก)        (รายการพฤติกรรม)    (สัญญาณเตือน)      (จอมอนิเตอร์)
```

## โครงสร้าง
| ไฟล์ | หน้าที่ |
|---|---|
| `collector/collector.py` | ตัวหลัก: อ่าน JSON ทีละบรรทัด → normalize → เก็บ → เทียบกฎ → alert |
| `collector/normalize.py` | แปลง log ดิบเป็นฟิลด์ Sigma (Image, ParentImage, CommandLine, TargetFilename …) |
| `collector/store.py` | สร้าง/เขียน SQLite ตาราง `events`, `alerts` |
| `engine/rules.py` | อ่านกฎ YAML และเทียบกับ event (contains/startswith/endswith/re/all, and/or/not) |
| `rules/MD-00xx.yml` | กฎ 25 ข้อ แต่ละข้อมี `plain_th` = คำอธิบายภาษาคน |
| `dashboard/app.py` | คอนโซล 4 หน้า: ภาพรวม, ภัยคุกคาม (process tree + ตัดสิน TP/FP), ค้นหา Event, กฎ & ATT&CK coverage |
| `attacksim/run_atomic.sh` | รัน Atomic Red Team ตามแผน + จดช่วงเวลาลง `data/runs.csv` |
| `attacksim/baseline.sh` | จดช่วงใช้งานปกติ ไว้วัด False Positive |
| `scripts/report.py` | คำนวณ Detection Rate, Latency, FP/ชม., Precision สำหรับบทที่ 4 |
| `tests/test_rules.py` | ทดสอบทุกกฎด้วย event จำลอง |
| `.streamlit/config.toml` | ธีมสีของ Dashboard |
| `practice/` | โค้ดฝึกที่เขียนเองระหว่างเรียน (ไม่ใช่ส่วนของระบบ) |
| `docs/` | เล่มโครงงาน, ร่างบท, คู่มืออ่านโค้ด |

## ใช้งาน (ดับเบิลคลิก)
1. `start_collector.command` — เริ่มเก็บและตรวจจับ (กรอกรหัสผ่านเครื่อง 1 ครั้ง)
2. `start_dashboard.command` — เปิด Dashboard ที่ http://localhost:8501

## ทดสอบโดยไม่ต้องใช้ sudo
```bash
python tests/test_rules.py
python collector/collector.py --file tests/sample_events.jsonl --db data/test.db
DETECT_DB=data/test.db streamlit run dashboard/app.py
```

## ทดลองด้วย Atomic Red Team (ครั้งแรกต้องติดตั้ง)
```bash
brew install --cask powershell
pwsh -c 'IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing); Install-AtomicRedTeam -getAtomics'
```
จากนั้น (เปิด collector ไว้อีกหน้าต่าง): `./attacksim/run_atomic.sh` แล้ว `python scripts/report.py`

## ข้อควรระวัง
- `data/` ไม่อยู่ใน git (มีข้อมูลจริงของเครื่อง) — ระบบไม่เก็บฟิลด์ `env` ของ eslogger
- ไม่รัน T1555.001 แบบอัตโนมัติ (dump-keychain อาจเปิดเผยรหัสผ่าน)
- tactic/technique ในกฎต้องตรวจกับ ATT&CK v19 อีกครั้งก่อนใส่ในเล่ม
- โครงสร้าง event fork/create/rename/unlink เขียนตามเอกสาร ควรเทียบกับ log จริง
