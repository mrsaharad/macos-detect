"""
Normalizer — แปลง event ดิบจาก eslogger ให้เป็นฟิลด์มาตรฐานแบบ Sigma

เปรียบเหมือน "หัวแปลงปลั๊ก": log ของ eslogger ซ้อนกันหลายชั้นและชื่อยาว
แต่กฎ Sigma ใช้ชื่อสั้นมาตรฐาน (Image, CommandLine, ...) ไฟล์นี้แปลงให้ตรงกัน
ถ้าวันหนึ่ง Apple เปลี่ยนโครงสร้าง log แก้ที่ไฟล์นี้ไฟล์เดียว กฎไม่ต้องแตะ

ฟิลด์ที่ได้ (ชื่อตาม Sigma):
    Image           โปรแกรมที่ทำเหตุการณ์ (path เต็ม)
    ParentImage     โปรแกรมแม่ (eslogger ไม่ให้มา ต้องสร้างเองจาก cache)
    CommandLine     คำสั่งเต็ม (เฉพาะ exec)
    TargetFilename  ไฟล์ปลายทาง (create / rename / unlink)
    SourceFilename  ไฟล์ต้นทาง (rename)
    SigningId       ลายเซ็นของโปรแกรม เช่น com.apple.security
    User            euid (0 = root)

หมายเหตุ: ฟิลด์ env ใน log มีข้อมูลส่วนตัว — เราไม่เก็บเลย
หมายเหตุ: โครงสร้าง fork/create/rename/unlink เขียนตามเอกสาร Endpoint Security
          และเขียนแบบป้องกันค่าหาย (.get) ไว้ ควรเทียบกับ log จริงอีกครั้ง
"""
import os
from urllib.parse import unquote

from redact import redact

# ชนิด event ที่เราสนใจ — แยกด้วย "ชื่อลิ้นชัก" ใน e["event"] แทนการจำเลข event_type
EVENT_KINDS = ("exec", "fork", "create", "rename", "unlink",
               # v2: จับที่ "ผลลัพธ์" ของการกระทำ (ตรวจโครงสร้างกับ log จริงแล้ว 23 พ.ย. 2569)
               "close", "truncate", "setflags", "setextattr", "deleteextattr", "btm_launch_item_add")
# ชื่อสั้นที่เก็บในคอลัมน์ event_type
KIND_NAME = {"btm_launch_item_add": "btm_add"}

CS_ADHOC = 0x2                                   # codesigning_flags: เซ็นแบบ ad-hoc (ไม่มีผู้ออกใบรับรอง)
# flag ของไฟล์ (sys/stat.h) ที่ผู้โจมตีใช้
FILE_FLAGS = {0x8000: "hidden", 0x2: "uimmutable", 0x20000: "simmutable", 0x8: "opaque", 0x1: "nodump"}
# es_btm_item_type_t
BTM_TYPES = {0: "user_item", 1: "app", 2: "login_item", 3: "agent", 4: "daemon"}


def signature_type(p):
    """ประเภทลายเซ็นของโปรเซส: platform (ของระบบ Apple) / developer (มี Team ID) / adhoc / other"""
    if not isinstance(p, dict):
        return None
    if p.get("is_platform_binary"):
        return "platform"
    if (p.get("codesigning_flags") or 0) & CS_ADHOC:
        return "adhoc"
    if p.get("team_id"):
        return "developer"
    return "other"


def flag_names(flags):
    return ",".join(name for bit, name in FILE_FLAGS.items() if flags & bit) or str(flags)


def _path(file_obj):
    """ลิ้นชัก file ของ eslogger มีหน้าตา {"path": "...", ...} — ดึงเฉพาะ path"""
    if isinstance(file_obj, dict):
        return file_obj.get("path")
    return None


def _dest_path(dest):
    """ปลายทางของ create/rename มี 2 แบบ:
    1) existing_file  = ไฟล์มีอยู่แล้ว  -> {"existing_file": {"path": ...}}
    2) new_path       = ไฟล์ใหม่       -> {"new_path": {"dir": {"path": ...}, "filename": ...}}
    """
    if not isinstance(dest, dict):
        return None
    if dest.get("existing_file"):
        return _path(dest["existing_file"])
    new = dest.get("new_path")
    if isinstance(new, dict):
        folder = _path(new.get("dir")) or ""
        return os.path.join(folder, new.get("filename") or "")
    return None


class Normalizer:
    def __init__(self):
        # cache: pid -> path ของโปรแกรม ใช้หา ParentImage
        # (eslogger บอกแค่ "เลข" ppid ไม่บอกว่าแม่คือโปรแกรมอะไร)
        self.pid_image = {}
        self.pid_signing = {}          # v2: pid -> signing id (ใช้เป็น ParentSigningId)

    def normalize(self, e):
        """รับ dict ดิบ 1 event -> คืน dict ฟิลด์มาตรฐาน (หรือ None ถ้าไม่สนใจ)"""
        ev = e.get("event") or {}
        if "exit" in ev:
            # โปรเซสจบแล้ว: ลบออกจาก cache (ไม่เก็บลงฐานข้อมูล) กันแรมโตและกันข้อมูลค้าง
            pid = ((e.get("process") or {}).get("audit_token") or {}).get("pid")
            self.pid_image.pop(pid, None)
            self.pid_signing.pop(pid, None)
            return None
        kind = next((k for k in EVENT_KINDS if k in ev), None)
        if kind is None:
            return None
        # close เกิดบ่อยมาก (~90 ครั้ง/วินาที) เก็บเฉพาะครั้งที่ไฟล์ถูกแก้จริง (~5 ครั้ง/วินาที)
        if kind == "close" and not (ev["close"] or {}).get("modified"):
            return None

        proc = e.get("process") or {}          # โปรเซสที่ "ทำ" เหตุการณ์
        token = proc.get("audit_token") or {}
        pid = token.get("pid")
        ppid = proc.get("ppid")
        image = _path(proc.get("executable"))

        rec = {
            "ts_event": e.get("time"),
            "event_type": kind,
            "pid": pid,
            "ppid": ppid,
            "Image": image,
            "ParentImage": None,
            "CommandLine": None,
            "TargetFilename": None,
            "SourceFilename": None,
            "SigningId": proc.get("signing_id"),
            "User": token.get("euid"),
            "TeamId": proc.get("team_id"),
            "SignatureType": signature_type(proc),
            "ParentSigningId": None,
            "ExtAttr": None, "Flags": None, "FileSize": None, "ItemType": None, "ItemExecutable": None,
            "Seq": e.get("global_seq_num"),
        }
        rec["event_type"] = KIND_NAME.get(kind, kind)

        if kind == "exec":
            # exec = โปรเซสเดิม (pid เดิม) เปลี่ยนไปรันโปรแกรมใหม่
            x = ev["exec"] or {}
            target = x.get("target") or {}
            ttoken = target.get("audit_token") or {}
            rec["pid"] = ttoken.get("pid", pid)
            rec["Image"] = _path(target.get("executable"))
            # v2: ปิดรหัสผ่าน/token ในคำสั่งก่อนเก็บ (collector/redact.py)
            rec["CommandLine"] = redact(" ".join(str(a) for a in (x.get("args") or [])))
            rec["SigningId"] = target.get("signing_id") or rec["SigningId"]
            rec["User"] = ttoken.get("euid", rec["User"])
            rec["TeamId"] = target.get("team_id")
            rec["SignatureType"] = signature_type(target)

        elif kind == "fork":
            # fork = แม่แตกตัวเป็นลูก ลูกได้ pid ใหม่แต่โปรแกรมเดิม
            child = (ev["fork"] or {}).get("child") or {}
            ctoken = child.get("audit_token") or {}
            rec["ppid"] = pid
            rec["pid"] = ctoken.get("pid")
            rec["Image"] = _path(child.get("executable")) or image

        elif kind == "create":
            rec["TargetFilename"] = _dest_path((ev["create"] or {}).get("destination"))

        elif kind == "rename":
            r = ev["rename"] or {}
            rec["SourceFilename"] = _path(r.get("source"))
            rec["TargetFilename"] = _dest_path(r.get("destination"))

        elif kind == "unlink":
            rec["TargetFilename"] = _path((ev["unlink"] or {}).get("target"))

        elif kind in ("close", "truncate", "setflags", "setextattr", "deleteextattr"):
            x = ev[kind] or {}
            target = x.get("target") or {}
            rec["TargetFilename"] = _path(target)
            rec["FileSize"] = (target.get("stat") or {}).get("st_size")      # ขนาดหลังแก้ (0 = ถูกล้าง)
            if kind == "setflags":
                rec["Flags"] = flag_names(x.get("flags") or 0)
            elif kind in ("setextattr", "deleteextattr"):
                rec["ExtAttr"] = x.get("extattr")

        elif kind == "btm_launch_item_add":
            # โปรเซสที่รายงานคือ backgroundtaskmanagementd ผู้ "สั่ง" จริงอยู่ใน instigator
            x = ev[kind] or {}
            item = x.get("item") or {}
            inst = x.get("instigator") or {}
            if inst:
                rec["Image"] = _path(inst.get("executable")) or rec["Image"]
                rec["SigningId"] = inst.get("signing_id")
                rec["TeamId"] = inst.get("team_id")
                rec["SignatureType"] = signature_type(inst)
                rec["pid"] = (inst.get("audit_token") or {}).get("pid", rec["pid"])
                rec["ppid"] = inst.get("ppid", rec["ppid"])
            url = item.get("item_url") or ""
            rec["TargetFilename"] = unquote(url[7:]) if url.startswith("file://") else url
            rec["ItemType"] = BTM_TYPES.get(item.get("item_type"), str(item.get("item_type")))
            rec["ItemExecutable"] = x.get("executable_path")

        # หาโปรแกรมแม่จาก cache (ถ้าแม่เริ่มก่อนเปิด eslogger จะหาไม่เจอ = gap เล็กๆ)
        rec["ParentImage"] = self.pid_image.get(rec["ppid"])
        rec["ParentSigningId"] = self.pid_signing.get(rec["ppid"])

        # อัปเดต cache ให้ event ถัดไปใช้ (btm_add รายงาน instigator ซึ่งไม่ใช่โปรเซสที่ส่ง event จึงข้าม)
        if kind != "btm_launch_item_add" and rec["pid"] is not None and rec["Image"]:
            self.pid_image[rec["pid"]] = rec["Image"]
            if rec["SigningId"]:
                self.pid_signing[rec["pid"]] = rec["SigningId"]
        return rec
