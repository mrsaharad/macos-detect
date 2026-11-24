"""
Redact — ปิดรหัสผ่าน / token ที่หลุดมาใน command line ก่อนเก็บลงฐานข้อมูล (v2)

command line ทุกคำสั่งในเครื่องถูกเก็บถาวร ถ้าผู้ใช้หรือโปรแกรมส่งรหัสผ่านเป็นอาร์กิวเมนต์
(เช่น curl -u user:pass, mysql -pXXX, --token=...) ข้อมูลลับจะอยู่ใน detect.db ไปด้วย
ไฟล์นี้แทนค่าที่เป็นความลับด้วย [REDACTED] แต่คงชื่อคำสั่งและตัวเลือกไว้ กฎยังจับได้ตามเดิม
"""
import re

R = "[REDACTED]"

_PATTERNS = [
    # --password=xxx  --token xxx  --api-key=xxx  --secret xxx  (ทั้งแบบ = และเว้นวรรค)
    (re.compile(r"(?i)((?<!\S)--?(?:password|passwd|pass|token|api[-_]?key|secret|access[-_]?key|client[-_]?secret)"
                r"(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)"), r"\1" + R),
    # key=value ในคำสั่ง/URL: password=..., token=..., apikey=..., secret=...
    (re.compile(r"(?i)\b((?:password|passwd|pwd|token|api[-_]?key|apikey|secret|access_token)=)([^\s&\"']+)"),
     r"\1" + R),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)(\S+)"), r"\1" + R),
    # curl/wget/http -u user:pass (เฉพาะโปรแกรมรับส่งข้อมูล — date -u, sudo -u ใช้ -u ความหมายอื่น)
    (re.compile(r"(\b(?:curl|wget|http|https|git|svn|ftp|lftp)\b[^|;&]*?\s(?:-u|--user)\s+)([^\s:]+):(\S+)"),
     r"\1\2:" + R),
    # URL ที่ฝัง user:pass@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]+):([^\s/@]+)@"), r"\1:" + R + "@"),
    # mysql -pXXX (ติดกับ -p)
    (re.compile(r"(\bmysql\S*\s.*?\s-p)(\S+)"), r"\1" + R),
    # security add-generic-password ... -w <password>
    (re.compile(r"(\bsecurity\s+add-(?:generic|internet)-password\b.*?\s-w\s+)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1" + R),
    # token รูปแบบที่รู้จัก: GitHub, Slack, AWS access key, OpenAI/Anthropic-style, JWT
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
                r"|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), R),
]


def redact(text):
    if not text:
        return text
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
