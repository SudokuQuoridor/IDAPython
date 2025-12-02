from idc import *
from ida_name import *

# string.txt 경로
FILE_PATH = r""

def apply_names_from_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] 파일을 열 수 없음: {e}")
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue  # 빈 줄/주석 무시

        parts = line.split()
        if len(parts) < 2:
            print(f"[!] 무시됨 (잘못된 형식): {line}")
            continue

        addr_str, name = parts[0], parts[1]

        try:
            ea = int(addr_str, 16)
        except ValueError:
            print(f"[!] 주소 변환 실패: {addr_str}")
            continue

        # 1. QWORD로 재정의 (8바이트)
        flags = get_full_flags(ea)
        if not is_qword(flags):
            try:
                doData(ea, FF_QWORD, 8)
            except Exception as e:
                print(f"[!] {hex(ea)} QWORD 정의 실패: {e}")
                continue

        # 2. 이름 강제 적용
        if set_name(ea, name, SN_NOWARN | SN_FORCE):
            print(f"[+] {hex(ea)} → {name} 적용 성공")
        else:
            print(f"[!] {hex(ea)} 이름 적용 실패")

# 실행
apply_names_from_file(FILE_PATH)
