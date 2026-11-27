"""เพิ่มหัวข้อ 2.5 งานและเครื่องมือที่เกี่ยวข้อง (C11) และรายการบรรณานุกรมใหม่
แหล่งที่ตรวจแล้ว (27 พ.ย. 2569):
  Virkud et al. 2024 — หน้า USENIX + ข้อความใน PDF (48%–55% เชิงพาณิชย์, Sigma 79%)
  Santa — github.com/northpolesec/santa (binary authorization, hash/certificate/Team ID/Signing ID/CDHash, ES)
  BlockBlock — objective-see.org/products/blockblock.html (persistence monitor, ES)
  Mac Monitor — Dalton (2023) "Introducing: Mac Monitor" Red Canary blog (ES + System Extension)
  osquery 5 — Trail of Bits (2021, Nov 10) es_process_events
  Elastic detection-rules — prebuilt rule docs: macOS EQL rules, require Elastic Defend"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import thesislib as T  # noqa: E402

T.open_doc(sys.argv[1])
E = T.Ed(T.read_doc())

tools = [
    ("Santa", "ควบคุมการรันโปรแกรม (binary authorization)",
     "อนุญาตหรือบล็อกโปรแกรมก่อนรัน ตามค่าแฮช ใบรับรอง Team ID, Signing ID หรือ CDHash",
     "ตัดสินที่ตัวโปรแกรม ไม่ได้ตรวจพฤติกรรมของโปรแกรมที่ได้รับอนุญาต"),
    ("BlockBlock", "เฝ้าดูการฝังตัว", "แจ้งเตือนเมื่อมีรายการฝังตัวใหม่ และให้ผู้ใช้เลือกบล็อก",
     "ครอบคลุมเฉพาะยุทธวิธีการฝังตัว"),
    ("Mac Monitor", "แสดงเหตุการณ์ของระบบเพื่อวิจัยและคัดแยกมัลแวร์", "ผู้วิเคราะห์ดูและกรองเหตุการณ์เอง",
     "ไม่ได้มุ่งวัดอัตราการตรวจจับด้วยชุดทดสอบ"),
    ("osquery", "สืบค้นสถานะและเหตุการณ์ของเครื่องด้วย SQL", "ไม่มีกฎตรวจจับในตัว ส่งข้อมูลให้ระบบอื่นวิเคราะห์",
     "เป็นแหล่งข้อมูล ไม่ใช่ระบบตรวจจับ"),
]

xml = (
    T.h2("2.5 งานและเครื่องมือที่เกี่ยวข้อง")
    + T.intro("หัวข้อนี้ทบทวนเครื่องมือบน macOS ที่ใช้ Endpoint Security Framework ชุดกฎตรวจจับที่เปิดเผยต่อสาธารณะ "
              "และงานวิจัยที่ประเมินกฎตรวจจับด้วย MITRE ATT&CK เพื่อระบุว่าโครงงานนี้ต่างจากงานที่มีอยู่อย่างไร")
    + T.h3("2.5.1 เครื่องมือบน macOS ที่ใช้ Endpoint Security Framework")
    + T.body("Santa เป็นระบบควบคุมการรันโปรแกรมที่เริ่มพัฒนาโดย Google และปัจจุบันดูแลต่อโดย North Pole Security "
             "ทำงานเป็น System Extension ที่รับเหตุการณ์จาก Endpoint Security เพื่ออนุญาตหรือบล็อกการรันโปรแกรมตามค่าแฮช "
             "ใบรับรอง Team ID, Signing ID หรือ CDHash (North Pole Security, n.d.) Santa ตัดสินที่ตัวโปรแกรมก่อนรัน "
             "จึงใช้ป้องกันการโจมตีแบบ Living off the Land ได้จำกัด เพราะโปรแกรมของระบบมีลายเซ็นของ Apple และต้องได้รับอนุญาต")
    + T.body("BlockBlock ของ Objective-See เฝ้าดูตำแหน่งที่มัลแวร์ใช้ฝังตัว เช่น LaunchAgent และ LaunchDaemon "
             "และแจ้งเตือนเมื่อมีรายการฝังตัวใหม่เพื่อให้ผู้ใช้เลือกบล็อก (Objective-See, n.d.) ส่วน Mac Monitor ของ "
             "Red Canary เป็นเครื่องมือฟรีสำหรับเก็บและวิเคราะห์เหตุการณ์ของระบบเพื่องานวิจัยและการคัดแยกมัลแวร์ "
             "สร้างบน Endpoint Security และ System Extension (Dalton, 2023) และ osquery ซึ่งใช้สืบค้นสถานะของเครื่อง"
             "ด้วยภาษา SQL รองรับเหตุการณ์จาก Endpoint Security ตั้งแต่รุ่นที่ 5 ผ่านตาราง es_process_events "
             "(Trail of Bits, 2021) ความแตกต่างของเครื่องมือเหล่านี้กับโครงงานนี้สรุปได้ดังตารางที่ 2.4")
    + T.caption_tbl("ตารางที่ 2.4 เครื่องมือบน macOS ที่ใช้ Endpoint Security Framework")
    + T.table(["เครื่องมือ", "หน้าที่หลัก", "วิธีตัดสินหรือแสดงผล", "ความต่างจากโครงงานนี้"], tools,
              [1300, 2200, 2600, 2200])
    + T.after_table()
    + T.h3("2.5.2 ชุดกฎตรวจจับและการประเมินด้วย MITRE ATT&CK")
    + T.body("กฎตรวจจับสำหรับ macOS ที่เปิดเผยต่อสาธารณะมีทั้งคลังกฎของชุมชน SigmaHQ (SigmaHQ, n.d.-a) และกฎสำเร็จรูป"
             "ของ Elastic ซึ่งเขียนด้วยภาษา EQL และต้องใช้ข้อมูลจาก Elastic Defend (Elastic, n.d.) กฎเหล่านี้ส่วนใหญ่"
             "ตรวจที่ชื่อโปรแกรมและรูปแบบคำสั่ง ซึ่งเป็นแนวทางเดียวกับกฎของระบบรุ่นที่ 1 ในโครงงานนี้")
    + T.body("Virkud et al. (2024) วิเคราะห์ชุดกฎที่กำกับเทคนิค ATT&CK ของผลิตภัณฑ์เชิงพาณิชย์ 3 ราย ได้แก่ "
             "Carbon Black, Splunk และ Elastic และชุดกฎ Sigma พบว่าชุดกฎเชิงพาณิชย์ครอบคลุมเทคนิคร้อยละ 48–55 "
             "ส่วน Sigma ครอบคลุมร้อยละ 79 และสรุปว่าหลายเทคนิคเขียนเป็นกฎตรวจจับไม่ได้ และการมีกฎสำหรับเทคนิคหนึ่ง"
             "ไม่ได้หมายความว่าผลิตภัณฑ์จะตรวจจับภัยคุกคามจริงของเทคนิคนั้นได้เหมือนกัน การนับจำนวนเทคนิคที่มีกฎ"
             "จึงไม่เพียงพอสำหรับประเมินระบบตรวจจับ โครงงานนี้จึงวัดอัตราการตรวจจับจากการรันชุดทดสอบจริง "
             "แทนการนับจำนวนเทคนิคที่มีกฎ")
    + T.h3("2.5.3 ตำแหน่งของโครงงานนี้")
    + T.body("เมื่อเทียบกับงานข้างต้น โครงงานนี้ต่างออกไป 3 ประการ ประการแรก ใช้ eslogger ที่มากับระบบ จึงไม่ต้องขอสิทธิ์ "
             "Endpoint Security จาก Apple และผู้อื่นทำซ้ำได้ ประการที่สอง เปิดเผยกฎทั้งหมดและวัดผลโดยแยกชุดทดสอบที่ใช้"
             "ปรับกฎออกจากชุดที่ใช้วัดผล พร้อมทดสอบการหลบเลี่ยงและเปรียบเทียบกับกฎของ SigmaHQ บนข้อมูลชุดเดียวกัน "
             "ประการที่สาม วิเคราะห์ช่องว่างของการมองเห็นเพื่อแยกว่าเทคนิคที่ตรวจจับไม่ได้มีสาเหตุจากข้อมูลหรือจากกฎ "
             "ข้อจำกัดคือโครงงานนี้ทดสอบบนเครื่องเดียว ด้วยชุดทดสอบที่ส่วนใหญ่รันคำสั่งผ่าน shell "
             "และไม่ได้เปรียบเทียบกับผลิตภัณฑ์เชิงพาณิชย์โดยตรง")
)

# แทรกท้ายบทที่ 2: sectPr ของบทที่ 2 อยู่ใน pPr ของย่อหน้าสุดท้าย (ย่อหน้า Streamlit) → ย้าย sectPr ไปไว้ในย่อหน้าว่าง
# ท้ายเนื้อหาใหม่ เพื่อให้หัวข้อ 2.5 อยู่ในบทที่ 2 และบทที่ 3 ยังขึ้นหน้าใหม่
import re  # noqa: E402
ms = list(re.finditer(T.PAT, E.doc, re.S))
h = next(i for i, m in enumerate(ms) if not m.group(0).startswith("<w:tbl>") and T.ptext(m).strip() == "บทที่ 3")
last = ms[h - 1]
sect = re.search(r"<w:sectPr\b.*?</w:sectPr>", last.group(0), re.S)
assert sect and T.ptext(last).startswith("โครงงานนี้ใช้ Streamlit"), "ไม่พบ sectPr ในย่อหน้าสุดท้ายของบทที่ 2"
moved = last.group(0).replace(sect.group(0), "")
E.doc = (E.doc[:last.start()] + moved + xml
         + f'<w:p><w:pPr><w:spacing w:after="0"/>{sect.group(0)}</w:pPr></w:p>' + E.doc[last.end():])

# ---------- บรรณานุกรม (เรียงตามรูปแบบเดิม: บทความวิชาการก่อน แล้วแหล่งออนไลน์ตามตัวอักษร) ----------
RPR_I = T.RPR.replace("<w:color", "<w:i/><w:iCs/><w:color")


def add_after(prefix, text):
    """text ใช้ *...* แทนส่วนที่เป็นตัวเอียง (ชื่อเรื่องตาม APA) ใช้ pPr ของรายการเดิม"""
    m = E.para(prefix)
    ppr = re.search(r"<w:pPr>.*?</w:pPr>", m.group(0), re.S).group(0)
    runs = "".join(T.run(p, RPR_I if i % 2 else T.RPR) for i, p in enumerate(text.split("*")) if p)
    E.doc = E.doc[:m.end()] + f"<w:p>{ppr}{runs}</w:p>" + E.doc[m.end():]


add_after("Sokolova, M.",
          "Virkud, A., Inam, M. A., Riddle, A., Liu, J., Wang, G., & Bates, A. (2024). How does endpoint detection use "
          "the MITRE ATT&CK framework? In *Proceedings of the 33rd USENIX Security Symposium* (pp. 3891–3908). "
          "USENIX Association.")
add_after("Apple Inc. (2022). What’s new in Endpoint Security",
          "Dalton, B. (2023). *Introducing: Mac Monitor*. Red Canary. Retrieved from "
          "https://redcanary.com/blog/threat-detection/mac-monitor/")
add_after("Dalton, B. (2023)",
          "Elastic. (n.d.). *Detection rules* [GitHub repository]. Retrieved from https://github.com/elastic/detection-rules")
add_after("Moonlock Lab. (2025",
          "North Pole Security. (n.d.). *Santa* [GitHub repository]. Retrieved from https://github.com/northpolesec/santa")
add_after("North Pole Security. (n.d.)",
          "Objective-See. (n.d.). *BlockBlock*. Retrieved from https://objective-see.org/products/blockblock.html")
add_after("Streamlit. (n.d.)",
          "Trail of Bits. (2021, November 10). *Announcing osquery 5: Now with EndpointSecurity on macOS*. Retrieved from "
          "https://blog.trailofbits.com/2021/11/10/announcing-osquery-5-now-with-endpointsecurity-on-macos/")
T.write_doc(E.doc)
