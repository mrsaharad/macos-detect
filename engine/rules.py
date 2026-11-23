"""
Rule Engine — อ่านกฎ Sigma-style (YAML) แล้วเทียบกับ event

รองรับ Sigma ฉบับย่อ:
    ฟิลด์|modifier : ค่า
        (ไม่มี modifier) = เท่ากันทุกตัวอักษร
        contains        = มีคำนี้ตรงไหนก็ได้        (เหมือน SQL LIKE '%x%')
        startswith      = ขึ้นต้นด้วย                (เหมือน LIKE 'x%')
        endswith        = ลงท้ายด้วย                 (เหมือน LIKE '%x')
        re              = regular expression
        |all            = ค่าใน list ต้องตรง "ทุกค่า" (ปกติ list = ตรงค่าใดค่าหนึ่ง)
    ในหนึ่ง selection: ทุกฟิลด์ต้องตรง (AND)   ค่าแบบ list = OR
    condition: and / or / not / วงเล็บ / "1 of sel*" / "all of sel*"
การเทียบไม่สนตัวพิมพ์เล็ก-ใหญ่ (ตามมาตรฐาน Sigma)
ไม่ใช้ eval() — แยก condition ด้วย parser เล็กๆ ของเราเอง (ปลอดภัยกว่า)
"""
import fnmatch
import glob
import os
import re

import yaml

# logsource.category ของ Sigma -> ชนิด event ของเรา
CATEGORY_TO_EVENTS = {
    "process_creation": {"exec"},
    "process_fork": {"fork"},
    "file_event": {"create", "rename"},   # rename ปลายทาง = ไฟล์ใหม่ปรากฏ
    "file_rename": {"rename"},
    "file_delete": {"unlink"},
    # v2: event ชนิดใหม่จาก Endpoint Security (ไม่ใช่ category มาตรฐานของ Sigma — กำหนดเองสำหรับ macOS)
    "file_flags": {"setflags"},                 # chflags / os.chflags (เช่น ซ่อนไฟล์)
    "file_xattr_set": {"setextattr"},
    "file_xattr_delete": {"deleteextattr"},     # ลบ extended attribute (เช่น ป้ายกักกัน)
    "file_modify": {"close", "truncate"},       # ไฟล์ถูกแก้ (close ที่ modified=true) หรือถูกตัด
    "launch_item_add": {"btm_add"},             # macOS ลงทะเบียน Login Item / LaunchAgent / LaunchDaemon
}


# ---------- เทียบค่า 1 ฟิลด์ ----------
def _match_one(value, pattern, mod):
    if value is None:
        return False
    v = str(value).lower()
    p = str(pattern).lower()
    if mod == "contains":
        return p in v
    if mod == "startswith":
        return v.startswith(p)
    if mod == "endswith":
        return v.endswith(p)
    if mod == "re":
        return re.search(str(pattern), str(value), re.IGNORECASE) is not None
    return v == p


def _match_field(rec, key, expected):
    """key เช่น 'Image|endswith' หรือ 'CommandLine|contains|all'"""
    parts = key.split("|")
    field, mods = parts[0], parts[1:]
    use_all = "all" in mods
    mod = next((m for m in mods if m != "all"), None)
    values = expected if isinstance(expected, list) else [expected]
    value = rec.get(field)
    if expected is None:                      # Sigma: ฟิลด์: null = ต้องว่าง
        return value in (None, "")
    hits = (_match_one(value, p, mod) for p in values)
    return all(hits) if use_all else any(hits)


def _match_selection(rec, sel):
    """selection แบบ dict = ทุกฟิลด์ต้องตรง, แบบ list ของ dict = ตรงอันใดอันหนึ่ง"""
    if isinstance(sel, list):
        return any(_match_selection(rec, s) for s in sel)
    return all(_match_field(rec, k, v) for k, v in sel.items())


# ---------- parser ของ condition ----------
_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class _Cond:
    def __init__(self, text, names):
        self.toks = _TOKEN.findall(text)
        self.i = 0
        self.names = names

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _take(self):
        t = self._peek()
        self.i += 1
        return t

    def parse(self):
        tree = self._or()
        if self._peek() is not None:
            raise ValueError(f"condition มีส่วนเกิน: {self.toks[self.i:]}")
        return tree

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self._take()
            left = ("or", left, self._and())
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self._take()
            left = ("and", left, self._not())
        return left

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        t = self._take()
        if t == "(":
            node = self._or()
            if self._take() != ")":
                raise ValueError("วงเล็บไม่ครบ")
            return node
        if t in ("1", "all") and self._peek() == "of":
            self._take()
            pat = self._take()
            pat = "*" if pat == "them" else pat
            matched = [n for n in self.names if fnmatch.fnmatch(n, pat)]
            return ("any" if t == "1" else "all", matched)
        if t not in self.names:
            raise ValueError(f"ไม่รู้จัก selection ชื่อ '{t}'")
        return ("sel", t)


def _eval(node, rec, det):
    op = node[0]
    if op == "sel":
        return _match_selection(rec, det[node[1]])
    if op == "not":
        return not _eval(node[1], rec, det)
    if op == "and":
        return _eval(node[1], rec, det) and _eval(node[2], rec, det)
    if op == "or":
        return _eval(node[1], rec, det) or _eval(node[2], rec, det)
    if op == "any":
        return any(_match_selection(rec, det[n]) for n in node[1])
    if op == "all":
        return all(_match_selection(rec, det[n]) for n in node[1])
    raise ValueError(op)


# ---------- กฎ 1 ข้อ ----------
class Rule:
    def __init__(self, data, path=""):
        self.path = path
        self.id = data["id"]
        self.title = data["title"]                       # ชื่อกฎ (อังกฤษ ตามธรรมเนียม Sigma)
        self.title_th = data.get("title_th", "")          # ชื่อภาษาไทย (ใช้ในเล่ม)
        self.description = data.get("description", "")    # คำอธิบายภาษาอังกฤษ (แสดงบน Dashboard)
        self.level = data.get("level", "medium")
        self.plain_th = data.get("plain_th", "")
        tags = data.get("tags", [])
        # tags แบบ Sigma: attack.credential_access, attack.t1555.001
        techs = [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d", t)]
        tacs = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.match(r"attack\.t\d", t)]
        self.technique = ",".join(techs)
        self.tactic = ",".join(tacs)
        cat = (data.get("logsource") or {}).get("category", "process_creation")
        self.events = CATEGORY_TO_EVENTS[cat]
        det = dict(data["detection"])
        self.condition_text = det.pop("condition")
        self.detection = det
        self.tree = _Cond(self.condition_text, list(det)).parse()   # ตรวจ syntax ตั้งแต่โหลด

    def matches(self, rec):
        if rec.get("event_type") not in self.events:
            return False
        return _eval(self.tree, rec, self.detection)


def load_rules(folder):
    rules = []
    for path in sorted(glob.glob(os.path.join(folder, "*.yml"))):
        with open(path, encoding="utf-8") as f:
            rules.append(Rule(yaml.safe_load(f), path))
    return rules
