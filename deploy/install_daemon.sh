#!/bin/zsh
# v2: ติดตั้ง collector เป็น LaunchDaemon (สิทธิ์ root, เริ่มเองเมื่อเปิดเครื่อง, launchd เปิดใหม่ถ้าถูกปิด)
# ทำไม: v1 รัน collector ด้วยสิทธิ์ผู้ใช้ มัลแวร์สิทธิ์เดียวกัน kill หรือแก้ไฟล์กฎ/ฐานข้อมูลได้ (ดู 3.1.7)
#   - โค้ด กฎ และฐานข้อมูล ถูกคัดลอกไปไว้ใน /Library/Application Support/macdetect เป็นของ root:wheel
#     (ผู้ใช้อ่านได้ แก้ไม่ได้) — ไม่รันจากโฟลเดอร์โปรเจคที่ผู้ใช้แก้ได้ ไม่งั้นแก้โค้ดแล้วได้สิทธิ์ root
#   - ใช้ /usr/bin/python3 ของระบบ (root:wheel) ไม่ใช้ Python.framework ที่กลุ่ม admin เขียนทับได้
#   - ต้องให้สิทธิ์ Full Disk Access กับ Python ของระบบ (System Settings → Privacy & Security → Full Disk Access)
#     ไม่งั้น Endpoint Security จะไม่ยอมให้ eslogger ทำงาน
# วิธีใช้:  sudo ./deploy/install_daemon.sh        ถอนการติดตั้ง: sudo ./deploy/uninstall_daemon.sh
set -e
[[ $EUID -eq 0 ]] || { echo "ต้องรันด้วย sudo"; exit 1; }
SRC=${0:A:h}/..
APP="/Library/Application Support/macdetect"
LABEL=com.macdetect.collector
PLIST=/Library/LaunchDaemons/$LABEL.plist
PY=/usr/bin/python3

rm -rf "$APP/app"                     # ล้างโค้ดเก่า (ไม่แตะ data)
mkdir -p "$APP/app" "$APP/data"
cp -R "$SRC/collector" "$SRC/engine" "$SRC/rules" "$APP/app/"
mkdir -p "$APP/app/lib"
cp -R "$SRC"/.venv/lib/python3*/site-packages/yaml "$APP/app/lib/"      # PyYAML แบบ pure Python
find "$APP/app" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:wheel "$APP"
chmod -R u=rwX,go=rX "$APP"

cat > $PLIST <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>-B</string><string>$APP/app/collector/collector.py</string>
    <string>--spawn</string><string>--quiet</string><string>--no-sound</string>
    <string>--db</string><string>$APP/data/detect.db</string>
    <string>--rules</string><string>$APP/app/rules</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>PYTHONPATH</key><string>$APP/app/lib</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardErrorPath</key><string>/Library/Logs/macdetect.log</string>
</dict></plist>
PL
chown root:wheel $PLIST; chmod 644 $PLIST
launchctl bootout system/$LABEL 2>/dev/null || true
launchctl bootstrap system $PLIST
sleep 3
launchctl print system/$LABEL | grep -E "state|pid" | head -3
echo "\nติดตั้งแล้ว  ฐานข้อมูล: $APP/data/detect.db  log: /Library/Logs/macdetect.log"
echo "Dashboard:  DETECT_DB=\"$APP/data/detect.db\" streamlit run dashboard/app.py"
echo "ถ้า log มีข้อความ 'Not permitted' ให้เพิ่ม $PY ใน Full Disk Access แล้วรัน: sudo launchctl kickstart -k system/$LABEL"
