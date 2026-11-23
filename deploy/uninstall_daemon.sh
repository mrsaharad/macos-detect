#!/bin/zsh
# ถอน LaunchDaemon ของ collector (ข้อมูลใน /Library/Application Support/macdetect/data ยังอยู่ ลบเองถ้าต้องการ)
[[ $EUID -eq 0 ]] || { echo "ต้องรันด้วย sudo"; exit 1; }
launchctl bootout system/com.macdetect.collector 2>/dev/null
rm -f /Library/LaunchDaemons/com.macdetect.collector.plist
echo "ถอนแล้ว (ข้อมูลยังอยู่ที่ /Library/Application Support/macdetect/data)"
