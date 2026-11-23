#!/bin/zsh
# แตก docx ล่าสุด → รันสคริปต์แก้ → zip → validate → render PDF (ยังไม่เขียนทับไฟล์เล่ม)
# วิธีใช้: docs/thesis_tools/scripts/apply.sh <สคริปต์แก้.py> <โฟลเดอร์ทำงาน>
set -e
ROOT=${0:A:h}/../../..
DOCX="$ROOT/docs/ระบบตรวจจับภัยคุกคามบน macOS ด้วยข้อมูลระดับระบบปฏิบัติการ by claude.docx"
SK="$HOME/Library/Application Support/Claude/local-agent-mode-sessions/skills-plugin/4035a46d-e372-48c2-986e-2da088d8b896/756263cf-06b9-4978-be2c-4a13e8fb6ac2/skills/docx/scripts"
W=$2; rm -rf "$W/u" "$W/out.docx" "$W/out.pdf"; mkdir -p "$W"
python3 -c "import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$DOCX" "$W/u"
"$ROOT/.venv/bin/python" "$1" "$W/u"
(cd "$W/u" && zip -XrDyq ../out.docx .)
python3 "$SK/office/validate.py" "$W/out.docx" --original "$DOCX" | tail -2
(cd "$W" && /Applications/LibreOffice.app/Contents/MacOS/soffice --headless --convert-to pdf out.docx >/dev/null 2>&1)
pdfinfo "$W/out.pdf" | grep Pages
