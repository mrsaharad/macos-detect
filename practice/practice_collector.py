import sys
import json

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    e = json.loads(line)
    print("pid = ",e["pid"])