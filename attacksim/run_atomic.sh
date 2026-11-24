#!/bin/zsh
# รัน Atomic Red Team ตามแผน แล้วบันทึกช่วงเวลา (ground truth) ลง data/runs.csv
# ใช้ framework ทางการ Invoke-AtomicRedTeam ของ Red Canary — สคริปต์นี้แค่ "กดปุ่ม" จดเวลา และคืนค่าเครื่อง
# วิธีใช้:  ./attacksim/run_atomic.sh dev          (รันชุด dev ตาม plan.txt)
#           ./attacksim/run_atomic.sh eval         (รันชุด eval)
#           ./attacksim/run_atomic.sh T1082        (รัน technique เดียว ตามเลข test ใน plan.txt)
#           ./attacksim/run_atomic.sh T1082 2,3    (รันเฉพาะ test ที่ระบุ)
#           ART_SET=dev-v2 ./attacksim/run_atomic.sh dev   (บันทึกชื่อชุดเป็น dev-v2 เช่น รันชุด dev ซ้ำกับ collector v2)
# รันทีละ test และบันทึกเวลา + exit code ของแต่ละ test ลง data/test_runs.csv (ใช้ตัดสินผลระดับ test อัตโนมัติ)
# ต้องเปิด collector ไว้อีกหน้าต่างก่อน และต้องรันใน Terminal (บาง test ใช้ sudo จะถามรหัสผ่าน 1 ครั้งตอนเริ่ม)
# ผลของแต่ละ test (prereqs / run / cleanup / ตรวจคืนค่า) เก็บไว้ที่ data/atomic_logs/<technique>.log
cd "$(dirname "$0")/.."
RUNS=data/runs.csv
LOGS=data/atomic_logs
mkdir -p $LOGS
[[ -f $RUNS ]] || echo "technique,set,start_utc,end_utc" > $RUNS
TRUNS=data/test_runs.csv
[[ -f $TRUNS ]] || echo "technique,test,set,root,start_utc,end_utc,exit_code" > $TRUNS
now() { date -u +"%Y-%m-%dT%H:%M:%S.000000Z"; }

# module ไม่ถูกโหลดอัตโนมัติเมื่อใช้ -NoProfile จึงต้อง Import-Module เองทุกครั้ง
MODULE=${ART_MODULE:-$HOME/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1}
if [[ ! -f $MODULE ]]; then
  echo "ไม่พบ Invoke-AtomicRedTeam ที่ $MODULE — ติดตั้งตาม README ก่อน"; exit 1
fi
ATOMICS=$HOME/AtomicRedTeam/atomics          # ระบุตรงๆ เพราะใต้ sudo ค่า HOME อาจเปลี่ยนเป็น /var/root
PS_CMD="Import-Module '$MODULE'; Invoke-AtomicTest"
PS_OPT="-PathToAtomicsFolder '$ATOMICS'"
art()      { pwsh -NoProfile -c "$PS_CMD $* $PS_OPT"; }
# test ที่ Atomic กำหนด elevation_required จะถูกข้ามถ้า PowerShell ไม่ได้รันเป็น root -> ใช้ sudo pwsh
art_root() { sudo pwsh -NoProfile -c "$PS_CMD $* $PS_OPT"; }
# รันทั้งสองกลุ่ม: $1 = technique, ที่เหลือ = ตัวเลือก (-GetPrereqs / -Cleanup / ว่าง)
art_both() {
  local t=$1; shift
  [[ -n $user_nums ]] && art $t -TestNumbers $user_nums $*
  [[ -n $root_nums ]] && art_root $t -TestNumbers $root_nums $*
  [[ -z $user_nums && -z $root_nums ]] && art $t $*
  return 0
}

# ---------- เลือกสิ่งที่จะรัน ----------
rows=("${(@f)$(grep -v '^#' attacksim/plan.txt | grep -v '^\s*$')}")
case "$1" in
  dev|eval) plan=(${(M)rows:#* $1 *}) ;;
  T*)       row=${(M)rows:#$1 *}
            [[ -n $2 ]] && plan=("$1 manual $2") || plan=("${row:-$1 manual}") ;;
  *)        echo "ใช้: $0 dev | eval | <technique> [เลข test]"; exit 1 ;;
esac
[[ ${#plan} -eq 0 ]] && { echo "ไม่มีรายการให้รัน"; exit 1; }

# ---------- sudo: ถามรหัสผ่านครั้งเดียว แล้วต่ออายุไว้จนจบ ----------
sudo -v || exit 1
while true; do sudo -n true; sleep 50; kill -0 $$ 2>/dev/null || exit; done 2>/dev/null &
KEEPALIVE=$!
trap 'kill $KEEPALIVE 2>/dev/null' EXIT

# ---------- สภาพเครื่องก่อนทดสอบ (ใช้คืนค่าเมื่อ cleanup ของ Atomic ใช้ไม่ได้บน macOS) ----------
BASH_FILES=(~/.bash_history ~/.bashrc ~/.bash_profile)
typeset -A EXISTED
for f in $BASH_FILES; do [[ -e $f || -L $f ]] && EXISTED[$f]=1; done
HAD_CRONTAB=0; crontab -l >/dev/null 2>&1 && HAD_CRONTAB=1

restore() {   # $1 = technique, ผลเขียนลง log
  local t=$1
  case $t in
    T1070.003|T1546.004)    # cleanup ของ Atomic ใช้ head -n -2 / sed -i ซึ่ง macOS ไม่รองรับ
      for f in $BASH_FILES; do
        if [[ -z ${EXISTED[$f]} && ( -e $f || -L $f ) ]]; then rm -f $f && echo "restore: ลบ $f ที่ test สร้างขึ้น"; fi
      done ;;
    T1053.003)
      [[ $HAD_CRONTAB == 0 ]] && crontab -r 2>/dev/null && echo "restore: ลบ crontab ที่ test สร้าง (เดิมไม่มี)" ;;
  esac
  # ตรวจว่าเครื่องกลับสู่สภาพปลอดภัย
  echo "check: Gatekeeper = $(spctl --status 2>&1)"
  local left=(~/Library/LaunchAgents/com.atomicredteam*(N) /Library/LaunchAgents/com.atomicredteam*(N)
              /Library/LaunchDaemons/com.atomicredteam*(N))
  left+=($(sudo sh -c 'ls /var/root/Library/LaunchAgents/com.atomicredteam* 2>/dev/null'))
  for f in $left; do echo "check: ⚠️ เหลือไฟล์ $f"; done
}

for row in $plan; do
  parts=(${=row}); tech=$parts[1]; grp=$parts[2]; nums=$parts[3]
  # แยกเลข test: มี ! = ต้องรันเป็น root
  all=(${(s:,:)nums}); user_nums=${(j:,:)${all:#*!}}; root_nums=${(j:,:)${${(M)all:#*!}%!}}
  log=$LOGS/$tech.log
  echo "\n===== $tech ($grp) test ${nums:-ทั้งหมด} ====="
  { echo "### $tech ($grp) test ${nums:-all} $(now)"; echo "--- prereqs"; } > $log
  art_both $tech -GetPrereqs >> $log 2>&1
  grp=${ART_SET:-$grp}
  start=$(now)
  echo "--- run (start $start)" >> $log
  if [[ -z $nums ]]; then
    art_both $tech 2>&1 | tee -a $log
  else
    for n in $all; do                       # ทีละ test: เว้นช่วง 6 วินาที (event ของ btm มาช้ากว่าคำสั่ง 1–5 วินาที)
      num=${n%!}; [[ $n == *! ]] && runner=art_root || runner=art
      tstart=$(now)
      out=$($runner $tech -TestNumbers $num 2>&1)
      print -r -- "$out" | tee -a $log
      sleep 6
      code=$(print -r -- "$out" | grep -o 'Exit code: -*[0-9]*' | tail -1 | grep -o -- '-*[0-9]*$')
      echo "$tech,$num,$grp,$([[ $n == *! ]] && echo 1 || echo 0),$tstart,$(now),${code:-NA}" >> $TRUNS
    done
  fi
  sleep 3                                   # เผื่อเวลาให้ event ไหลเข้า collector
  end=$(now)
  echo "--- cleanup (end $end)" >> $log
  art_both $tech -Cleanup >> $log 2>&1
  restore $tech 2>&1 | tee -a $log
  echo "$tech,$grp,$start,$end" >> $RUNS
  sleep 2
done

# Gatekeeper ต้องกลับมาเปิดเสมอ (T1685-12 ปิดชั่วคราว)
if ! spctl --status 2>&1 | grep -q enabled; then
  echo "⚠️  Gatekeeper ยังปิดอยู่ — กำลังเปิดคืน"; sudo spctl --master-enable; spctl --status
fi
echo "\nบันทึกช่วงเวลาไว้ที่ $RUNS และ log ไว้ที่ $LOGS/ แล้ว  ต่อไปรัน: python scripts/report.py"
