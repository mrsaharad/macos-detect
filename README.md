# macos-detect — ระบบตรวจจับภัยคุกคามบน macOS ด้วยข้อมูลระดับระบบปฏิบัติการ

ปริญญานิพนธ์ วิศวกรรมคอมพิวเตอร์ มหาวิทยาลัยรังสิต ปีการศึกษา 2569

ระบบตรวจจับและแจ้งเตือน (detection-only) ที่อ่านเหตุการณ์จาก Endpoint Security Framework ผ่าน `eslogger` ซึ่งมากับ macOS
แล้วเทียบกับกฎแบบ Sigma ที่เปิดเผยทั้งหมด และแสดงผลบน Dashboard

```
eslogger (2 โปรเซส) ──► Collector ──► Normalizer ──► SQLite (events) ──► Rule Engine ──► SQLite (alerts) ──► Dashboard
  หลัก + close          LaunchDaemon    ฟิลด์ Sigma        + health          33 กฎ YAML         + incident
```

## สองรุ่น

| | รุ่นที่ 1 (tag `v1`) | รุ่นที่ 2 (tag `v2`) |
|---|---|---|
| เหตุการณ์ | exec, fork, exit, create, rename, unlink | + close, truncate, setflags, setextattr, deleteextattr, btm_launch_item_add |
| กฎ | 26 ข้อ, 6 ยุทธวิธี ATT&CK | 33 ข้อ (+7 กฎที่ตรวจผลลัพธ์ของการกระทำ) |
| การทำงาน | เปิดเองใน Terminal | LaunchDaemon สิทธิ์ root, launchd เปิดใหม่ถ้าหยุด |
| อื่นๆ | — | ข้อมูลลายเซ็นโค้ด, ตรวจเหตุการณ์หล่น (heartbeat), ปิดรหัสผ่านในคำสั่ง, รวม alert เป็น incident |

## ผลการวัดหลัก

| | รุ่นที่ 1 | รุ่นที่ 2 |
|---|---|---|
| ชุดทดสอบที่ไม่ได้ใช้ปรับกฎ | 5/13 เทคนิค (38.5%) | 0/20 เทคนิค (ชุด hold-out ใหม่) — SigmaHQ ได้ 6/20 |
| Evasion (variant ที่ไม่เคยเห็น) | 0/12 | 6/12 — SigmaHQ ได้ 1/12 |
| การแจ้งเตือนเท็จช่วงใช้งานปกติ | 2.0 ครั้ง/ชม. (1 ชม.) | 1.5 ครั้ง/ชม. (16 ชม.) |
| ภาระต่อเครื่อง (1 คอร์) | CPU P95 3.93%, RAM 13 MB | CPU เฉลี่ย 3.5%, RAM 18 MB, 24 ชม. ไม่หยุด ไม่หล่น |

ข้อสรุป: ข้อมูลจาก Endpoint Security เพียงพอ ปัญหาอยู่ที่ความครอบคลุมของกฎ กฎที่ตรวจคำสั่ง (เช่น SigmaHQ) ครอบคลุมกว้างแต่หลบง่าย
กฎที่ตรวจผลลัพธ์ทนการหลบเลี่ยงแต่ครอบคลุมแคบ จึงควรใช้ร่วมกัน

## ติดตั้งและใช้งาน

ต้องใช้ macOS 13 ขึ้นไป (มี `eslogger`), Python 3.10 ขึ้นไป และบัญชีผู้ดูแลระบบ

```bash
git clone https://github.com/mrsaharad/macos-detect.git
cd macos-detect
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python tests/test_rules.py              # กฎทั้งหมด 33 ข้อ ผิด 0
```

**รุ่นที่ 2 (แนะนำ)** — ติดตั้งเป็น LaunchDaemon แล้วให้ Full Disk Access กับ `/usr/bin/python3`
(System Settings → Privacy & Security → Full Disk Access)

```bash
sudo ./deploy/install_daemon.sh         # ติดตั้งและเริ่มทำงาน (แก้กฎแล้วต้องรันซ้ำ)
DETECT_DB="/Library/Application Support/macdetect/data/detect.db" streamlit run dashboard/app.py
sudo ./deploy/uninstall_daemon.sh       # ถอนการติดตั้ง (ข้อมูลยังอยู่)
```

**รุ่นที่ 1** — ดับเบิลคลิก `start_collector.command` (กรอกรหัสผ่าน) แล้ว `start_dashboard.command`
(Terminal ต้องได้ Full Disk Access)

**ลองโดยไม่ต้องใช้ sudo** — ป้อนเหตุการณ์ตัวอย่างเข้า collector

```bash
python collector/collector.py --file tests/sample_events.jsonl --db data/test.db
DETECT_DB=data/test.db streamlit run dashboard/app.py
```

## ทดสอบและวัดผล

ต้องติดตั้ง PowerShell และ Invoke-AtomicRedTeam หนึ่งครั้ง

```bash
brew install powershell
pwsh -c 'IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing); Install-AtomicRedTeam -getAtomics'
```

| ขั้น | คำสั่ง |
|---|---|
| ชุด dev / eval (รุ่นที่ 1) | `./attacksim/run_atomic.sh dev`, `./attacksim/run_atomic.sh eval`, `./attacksim/manual_tests.sh` |
| ชุด hold-out (รุ่นที่ 2) | `./attacksim/run_atomic.sh eval2` (คัดเลือกด้วย `attacksim/select_eval2.py`) |
| การหลบเลี่ยง | `python attacksim/evasion.py --version v2` |
| ภาระสูง / A/B | `python attacksim/stress.py stress --version v2`, `python attacksim/stress.py ab --version v2 --state on` |
| ใช้งานปกติ / 24 ชม. | `./attacksim/baseline.sh 480`, `./attacksim/stability.sh 1440` |
| คำนวณผล | `python scripts/report.py`, `python scripts/compare_sigmahq.py --v2` |

กับฐานข้อมูลของ LaunchDaemon ให้ตั้ง `DETECT_DB="/Library/Application Support/macdetect/data/detect.db"` ก่อน
ล็อกกฎ (git tag) ก่อนรันชุดวัดผลทุกครั้ง และไม่แก้กฎหลังเห็นผล

## โครงสร้าง

| โฟลเดอร์ | เนื้อหา |
|---|---|
| `collector/` | `collector.py` ตัวหลัก (เปิด eslogger 2 โปรเซส, heartbeat), `normalize.py` แปลงเป็นฟิลด์ Sigma, `redact.py` ปิดข้อมูลลับ, `store.py` SQLite |
| `engine/` | `rules.py` อ่านและเทียบกฎ, `incidents.py` รวม alert เป็น incident |
| `rules/` | กฎ `MD-0001`–`MD-0033` (YAML) แต่ละข้อมีคำอธิบายภาษาไทย `plain_th` |
| `dashboard/` | Dashboard บน Streamlit (Overview, Alerts/Incidents, Event search, Rules & ATT&CK) |
| `deploy/` | ติดตั้ง/ถอน LaunchDaemon |
| `attacksim/` | สคริปต์รันชุดทดสอบ, evasion, stress, baseline และบันทึกการคัดเลือก test |
| `scripts/` | คำนวณตัวชี้วัด, วัด CPU/RAM, เทียบ SigmaHQ |
| `tests/` | ทดสอบกฎด้วยเหตุการณ์จำลอง |
| `docs/` | บันทึกความคืบหน้า, สคริปต์ทำเล่ม, เอกสารเตรียมสอบ (ไฟล์เล่ม .docx ไม่อยู่ใน repo) |
| `practice/` | โค้ดฝึกระหว่างเรียน (ไม่ใช่ส่วนของระบบ) |

## ข้อควรระวัง

- ระบบตรวจจับอย่างเดียว ไม่บล็อก และผู้ที่ได้สิทธิ์ root ยังปิดระบบได้
- Apple ระบุว่ารูปแบบผลลัพธ์ของ `eslogger` อาจเปลี่ยนเมื่ออัปเดต — ตรวจกับ macOS 27.2 แล้ว
- `data/` ไม่อยู่ใน git เพราะมีข้อมูลจริงของเครื่อง ระบบไม่เก็บตัวแปร `env` ของโปรเซส
- ชุดทดสอบบางตัวแก้การตั้งค่าเครื่องชั่วคราว ควรรันบนเครื่องทดสอบ ไม่ใช่เครื่องที่มีข้อมูลสำคัญ
- รหัสเทคนิคใช้ MITRE ATT&CK v19 (ตรวจชื่อกับ v20.1 แล้วตรงกัน)
