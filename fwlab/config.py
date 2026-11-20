"""路径与常量。"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"
RAW = WORK / "raw"
UNPACK = WORK / "unpack"
REPORTS = ROOT / "reports"
FWTOOL = Path(os.environ.get("FWTOOL", ROOT / "third_party" / "fwtool.py" / "fwtool.py"))

# 官方固件：ILCE-7RM3 System Software Ver.3.10 (Windows)
FW_URL = "https://di.update.sony.net/IMT/Update_ILCE7RM3V310.exe"
FW_NAME = "Update_ILCE7RM3V310.exe"
FW_SIZE = 313_011_160  # 官方页面标注 313,011,160 bytes

DAT_NAME = "FirmwareData_ILCE7RM3V310.dat"

DAT_MAGIC = b"\x89UFU\r\n\x1a\n"
FDAT_MAGIC = b"UDTRFIRM"
