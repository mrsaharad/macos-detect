#!/bin/zsh
# ทดสอบความเสถียร: collector + eslogger ต้องทำงานต่อเนื่องครบ 24 ชม. โดยไม่หยุด (ตามแผนงานบทที่ 1)
# วัด CPU/RAM ทุก 60 วินาทีตลอดช่วง → data/results/stability.csv และ stability_summary.json
# ถ้า collector หยุดกลางทาง สคริปต์จะจบเองและบันทึกเวลาที่หยุดไว้ใน sensor_stopped_at
# วิธีใช้: เปิด start_collector.command ก่อน แล้วรัน  ./attacksim/stability.sh        (ค่าเริ่มต้น 1440 นาที = 24 ชม.)
# caffeinate -i -s กันเครื่องหลับระหว่างวัด (ต้องเสียบสายชาร์จ ถ้าใช้แบตเตอรี่ -s จะไม่มีผล)
cd "$(dirname "$0")/.."
mins=${1:-1440}
PY=python3; [[ -x .venv/bin/python ]] && PY=.venv/bin/python
echo "เริ่มทดสอบความเสถียร $mins นาที (ถึงประมาณ $(date -v+${mins}M '+%d/%m %H:%M'))"
echo "ห้ามปิดเครื่อง/รีสตาร์ท/ปิด Terminal ของ collector  |  ระหว่างนี้รัน baseline.sh 480 ช่วงใช้งานปกติได้"
caffeinate -i -s $PY scripts/measure_overhead.py --minutes $mins --interval 60 --tag stability
