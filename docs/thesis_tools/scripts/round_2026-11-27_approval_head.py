"""ผู้ใช้ยืนยันว่า ดร.ชนินท์ วงษ์ใหญ่ เป็นหัวหน้าภาค (27 พ.ย. 2569) → ลบหมายเหตุสีเทาบนหน้าอนุมัติ"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402

T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())
assert "(ดร. ชนินท์ วงษ์ใหญ่)" in E.doc
E.put(E.para("[ร่าง: ตรวจชื่อหัวหน้าหลักสูตรปัจจุบันกับภาควิชา]"), "")
assert "[ร่าง:" not in E.doc
T.write_doc(E.doc)
