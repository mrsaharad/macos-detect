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

# ชนิด event ที่เราสนใจ — แยกด้วย "ชื่อลิ้นชัก" ใน e["event"] แทนการจำเลข event_type
EVENT_KINDS = ("exec", "fork", "create", "rename", "unlink")


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

    def normalize(self, e):
        """รับ dict ดิบ 1 event -> คืน dict ฟิลด์มาตรฐาน (หรือ None ถ้าไม่สนใจ)"""
        ev = e.get("event") or {}
        if "exit" in ev:
            # โปรเซสจบแล้ว: ลบออกจาก cache (ไม่เก็บลงฐานข้อมูล) กันแรมโตและกันข้อมูลค้าง
            pid = ((e.get("process") or {}).get("audit_token") or {}).get("pid")
            self.pid_image.pop(pid, None)
            return None
        kind = next((k for k in EVENT_KINDS if k in ev), None)
        if kind is None:
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
        }

        if kind == "exec":
            # exec = โปรเซสเดิม (pid เดิม) เปลี่ยนไปรันโปรแกรมใหม่
            x = ev["exec"] or {}
            target = x.get("target") or {}
            ttoken = target.get("audit_token") or {}
            rec["pid"] = ttoken.get("pid", pid)
            rec["Image"] = _path(target.get("executable"))
            rec["CommandLine"] = " ".join(str(a) for a in (x.get("args") or []))
            rec["SigningId"] = target.get("signing_id") or rec["SigningId"]
            rec["User"] = ttoken.get("euid", rec["User"])

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

        # หาโปรแกรมแม่จาก cache (ถ้าแม่เริ่มก่อนเปิด eslogger จะหาไม่เจอ = gap เล็กๆ)
        rec["ParentImage"] = self.pid_image.get(rec["ppid"])

        # อัปเดต cache ให้ event ถัดไปใช้
        if rec["pid"] is not None and rec["Image"]:
            self.pid_image[rec["pid"]] = rec["Image"]
        return rec
