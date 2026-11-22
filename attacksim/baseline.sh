#!/bin/zsh
# บันทึกช่วง "ใช้เครื่องตามปกติ" (ไม่มีการโจมตี) ไว้วัด False Positive ต่อชั่วโมง
# วิธีใช้: ./attacksim/baseline.sh 60   (ใช้เครื่องปกติ 60 นาที ระหว่างนั้นเปิด collector ไว้)
cd "$(dirname "$0")/.."
mins=${1:-30}
RUNS=data/runs.csv; mkdir -p data
[[ -f $RUNS ]] || echo "technique,set,start_utc,end_utc" > $RUNS
start=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
echo "เริ่ม baseline $mins นาที — ใช้เครื่องตามปกติได้เลย (Ctrl+C เพื่อจบก่อนเวลา)"
trap 'true' INT
sleep $((mins*60))
end=$(date -u +"%Y-%m-%dT%H:%M:%S.000000Z")
echo "BASELINE,baseline,$start,$end" >> $RUNS
echo "บันทึก baseline แล้ว"
