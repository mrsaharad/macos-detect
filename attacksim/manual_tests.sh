#!/bin/zsh
# ทดสอบด้วยมือสำหรับ technique ที่ไม่มี Atomic test บน macOS (ชุด eval) แล้วจดช่วงเวลาลง data/runs.csv
#   T1686     Disable or Modify System Firewall — ใช้ socketfilterfw (เครื่องมือ firewall ของ macOS)
#             แล้วคืนสถานะเดิมเสมอ
#   T1059.006 Python — ใช้คำสั่งของ Atomic T1059.006-4 (เขียนไว้สำหรับ Linux) ซึ่งรันบน macOS ได้:
#             python3 -c "import pty;pty.spawn('/bin/sh')" แล้วสั่ง exit ทันที
#             (ไม่ใช้ test 1-3 เพราะดาวน์โหลด linpeas มารันจริง)
# วิธีใช้: ./attacksim/manual_tests.sh   (เปิด collector ไว้ก่อน; ถามรหัสผ่าน sudo 1 ครั้ง)
cd "$(dirname "$0")/.."
RUNS=data/runs.csv; LOGS=data/atomic_logs; mkdir -p $LOGS
[[ -f $RUNS ]] || echo "technique,set,start_utc,end_utc" > $RUNS
now() { date -u +"%Y-%m-%dT%H:%M:%S.000000Z"; }
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
sudo -v || exit 1

# ---- T1686 ----
log=$LOGS/T1686.log
before=$($FW --getglobalstate)
{ echo "### T1686 (eval, manual) $(now)"; echo "before: $before"; } > $log
start=$(now)
sudo $FW --setglobalstate off 2>&1 | tee -a $log
sleep 3; end=$(now)
if [[ $before == *enabled* ]]; then sudo $FW --setglobalstate on >> $log 2>&1; fi
echo "after: $($FW --getglobalstate)" | tee -a $log
echo "T1686,eval,$start,$end" >> $RUNS

sleep 2

# ---- T1059.006 ----
log=$LOGS/T1059.006.log
echo "### T1059.006 (eval, manual: Atomic T1059.006-4 command) $(now)" > $log
start=$(now)
echo exit | python3 -c "import pty;pty.spawn('/bin/sh')" >> $log 2>&1
echo "exit code: $?" >> $log
sleep 3; end=$(now)
echo "T1059.006,eval,$start,$end" >> $RUNS

echo "\nเสร็จ: บันทึกช่วงเวลาไว้ที่ $RUNS และ log ที่ $LOGS/T1686.log, T1059.006.log"
