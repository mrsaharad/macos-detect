"""ป้อนเหตุการณ์ทดสอบเข้า collector ตามเวลาจริง (time = เวลาที่ส่งออก) เพื่อให้ latency ในภาพหน้าจอเป็นค่าที่วัดได้จริง"""
import json, random, sys, time, datetime as dt
random.seed(11)
lines = [json.loads(l) for l in open("app/tests/sample_events.jsonl") if l.startswith("{")]
benign, attack = lines[:8], lines[8:]
DUR = 240
plan = [(random.uniform(0, DUR), random.choice(benign)) for _ in range(2400)]
plan += [(random.uniform(15, DUR - 10), a) for a in attack]
plan.sort(key=lambda x: x[0])
t0 = time.time()
for at, e in plan:
    d = at - (time.time() - t0)
    if d > 0:
        time.sleep(d)
    e = json.loads(json.dumps(e))
    e["time"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"
    sys.stdout.write(json.dumps(e) + "\n"); sys.stdout.flush()
