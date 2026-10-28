import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    e = json.loads(line)
    if e.get("event_type") != 9:
        continue
    ex = e["event"]["exec"]
    pid = ex["target"]["audit_token"]["pid"]
    ppid = e["process"]["ppid"]
    program = ex["target"]["executable"]["path"]
    args = " ".join(ex.get("args", []))
    print(pid, ppid, program, args)
