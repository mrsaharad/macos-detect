# คู่มืออ่านโค้ดตัวเอง (ไว้เรียนหลังสอบ)

อ่านตามลำดับนี้ ทีละไฟล์ ใช้ Feynman: อ่านจบแล้วอธิบายออกเสียงให้ได้โดยไม่ดูโค้ด

| ลำดับ | ไฟล์ | ใช้ความรู้เรื่อง | คำถามที่ต้องตอบได้ |
|---|---|---|---|
| 1 | `collector/collector.py` | `for line in sys.stdin`, `strip`, `startswith`, `continue`, `json.loads` (เรียนแล้ว!) | ทำไมต้อง `try/except JSONDecodeError`? ทำไมต้องบันทึกทันทีทุกแถว (autocommit) — ถ้าถือ transaction ค้างไว้จะเกิดอะไร? (คำใบ้: database is locked) |
| 2 | `collector/normalize.py` | dict ซ้อน `e["a"]["b"]`, `.get()` | ParentImage มาจากไหน? ถ้าแม่เปิดก่อนเริ่ม eslogger จะเป็นอะไร? |
| 3 | `collector/store.py` | SQL `CREATE TABLE`, `INSERT`, `?` | ทำไมใช้ `?` แทนการต่อ string? (คำใบ้: SQL injection) |
| 4 | `rules/MD-0002.yml` | YAML, Sigma | `selection and not filter_system` แปลว่าอะไร? |
| 5 | `engine/rules.py` | ฟังก์ชัน, class, recursion | `contains` ต่างจาก `endswith` ยังไง? (เทียบกับ SQL `LIKE '%x%'` / `'%x'`) |
| 6 | `dashboard/app.py` | pandas, Streamlit | Dashboard อ่านข้อมูลจากไหน? (ไม่ใช่จาก eslogger!) |
| 7 | `scripts/report.py` | การคำนวณสถิติ | Detection Rate, Latency, FP/ชม. คิดยังไง? |

## Python ที่ต้องรู้เพิ่ม (เรียงจากง่าย)
1. `.get("key")` — เปิดลิ้นชัก ถ้าไม่มีได้ `None` แทนการ error
2. `def` ฟังก์ชัน และ `return`
3. `try / except` — ดักไม่ให้โปรแกรมล้ม
4. `class` — กล่องที่รวมข้อมูล + ฟังก์ชัน (เช่น `Normalizer` จำ cache ไว้ในตัว)
5. list comprehension `[x for x in ...]`

## SQL ที่ต้องรู้ (ลองใน `sqlite3 data/detect.db`)
```sql
SELECT COUNT(*) FROM events;
SELECT Image, COUNT(*) FROM events GROUP BY Image ORDER BY 2 DESC LIMIT 10;   -- โปรแกรมที่เปิดบ่อยสุด
SELECT rule_id, title, COUNT(*) FROM alerts GROUP BY rule_id;
SELECT e.CommandLine FROM alerts a JOIN events e ON e.id = a.event_id;          -- JOIN สองตาราง
```

## ประโยคอธิบายกรรมการ
> "ระบบผมเหมือนกล้องวงจรปิดใน Mac: eslogger คือกล้อง, Collector คือ รปภ. ที่ดูกล้องและจดลงสมุด (SQLite),
> กฎคือรายการพฤติกรรมน่าสงสัย ถ้าเจอก็ส่งสัญญาณเตือนขึ้นจอ (Dashboard) ระบบตรวจจับอย่างเดียว ไม่บล็อก"
