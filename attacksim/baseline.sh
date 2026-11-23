#!/bin/zsh
# บันทึกช่วง "ใช้เครื่องตามปกติ" (ไม่มีการโจมตี) ไว้วัด False Positive ต่อชั่วโมง
# และวัด CPU/RAM ของ collector + eslogger ไปพร้อมกัน (scripts/measure_overhead.py)
# วิธีใช้: ./attacksim/baseline.sh 480  (ใช้เครื่องปกติ 8 ชม.; รอบนำร่องเดิมใช้ 60 นาที ระหว่างนั้นต้องเปิด collector ไว้)
cd "$(dirname "$0")/.."
mins=${1:-480}
RUNS=data/runs.csv; mkdir -p data
[[ -f $RUNS ]] || echo "technique,set,start_utc,end_utc" > $RUNS
PY=python3; [[ -x .venv/bin/python ]] && PY=.venv/bin/python

$PY scripts/measure_overhead.py --minutes $mins --interval 5 &
MEASURE=$!
caffeinate -i -s -w $MEASURE &     # กันเครื่องหลับจนกว่าการวัดจะจบ (ต้องเสียบสายชาร์จสำหรับ -s)
sleep 1
kill -0 $MEASURE 2>/dev/null || { echo "เริ่มตัววัดไม่ได้ — เปิด collector (start_collector.command) ก่อน"; exit 1; }

start=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
echo "เริ่ม baseline $mins นาที (ถึงประมาณ $(date -v+${mins}M +%H:%M)) — ใช้เครื่องตามปกติได้เลย"
echo "อย่ารันการทดสอบโจมตีระหว่างนี้  |  Ctrl+C = จบก่อนเวลา (ข้อมูลที่เก็บแล้วยังถูกบันทึก)"
trap 'kill -TERM $MEASURE 2>/dev/null' INT TERM
wait $MEASURE 2>/dev/null; wait $MEASURE 2>/dev/null     # รอรอบสองเผื่อ Ctrl+C ขัดจังหวะ wait รอบแรก
end=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
echo "BASELINE,baseline,$start,$end" >> $RUNS
echo "\nบันทึกช่วง baseline ลง $RUNS แล้ว  ต่อไปรัน: python scripts/report.py"
