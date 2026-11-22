#!/bin/zsh
# ดับเบิลคลิก = เริ่มเก็บ event + ตรวจจับ (ต้องกรอกรหัสผ่านเครื่อง 1 ครั้ง เพราะ eslogger ต้องใช้ sudo)
cd "$(dirname "$0")"
source .venv/bin/activate
echo "เริ่มระบบตรวจจับ... (หยุดด้วย Ctrl+C)"
sudo eslogger exec fork exit create rename unlink | python collector/collector.py
exec zsh
