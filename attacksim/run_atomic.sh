#!/bin/zsh
# รัน Atomic Red Team ตามแผน แล้วบันทึกช่วงเวลา (ground truth) ลง data/runs.csv
# ใช้ framework ทางการ Invoke-AtomicRedTeam ของ Red Canary — สคริปต์นี้แค่ "กดปุ่ม" และจดเวลา
# วิธีใช้:  ./attacksim/run_atomic.sh            (รันทุก technique ในแผน)
#           ./attacksim/run_atomic.sh T1082      (รันเฉพาะตัวที่ระบุ)
# ต้องเปิด collector ไว้อีกหน้าต่างก่อน
cd "$(dirname "$0")/.."
RUNS=data/runs.csv
mkdir -p data
[[ -f $RUNS ]] || echo "technique,set,start_utc,end_utc" > $RUNS
now() { date -u +"%Y-%m-%dT%H:%M:%S.000000Z"; }

if [[ -n "$1" ]]; then plan=("$1 manual"); else plan=("${(@f)$(grep -v '^#' attacksim/plan.txt | grep -v '^\s*$')}"); fi

for row in $plan; do
  tech=${row%% *}; grp=${row##* }
  echo "\n===== $tech ($grp) ====="
  pwsh -NoProfile -c "Invoke-AtomicTest $tech -GetPrereqs" >/dev/null 2>&1
  start=$(now)
  pwsh -NoProfile -c "Invoke-AtomicTest $tech"
  sleep 3                                   # เผื่อเวลาให้ event ไหลเข้า collector
  end=$(now)
  pwsh -NoProfile -c "Invoke-AtomicTest $tech -Cleanup" >/dev/null 2>&1
  echo "$tech,$grp,$start,$end" >> $RUNS
  sleep 2
done
echo "\nบันทึกช่วงเวลาไว้ที่ $RUNS แล้ว  ต่อไปรัน: python scripts/report.py"
