# 사용 용도: 샘플 분석 이후 분석중 재정의한 함수 목록을 추출하여 재분석시 활용

import idautils
import idc
import re

def extract_renamed_function():
    result = []
    # IDA에서 해석한 함수의 접두사 목록
    pattern = r"^(sub_|unknown|\?|null|j_|__acrt|__dcrt|__vcrt|__scrt)\w*"

    print("++++++ Extract Renamed Functions ++++++")
    for addr in idautils.Functions():
        try:    
            func_name = idc.get_func_name(addr)

            if not re.match(pattern, func_name):
                print(f"[OK] Renamed Function 0x{addr:X}: {func_name}")
                result.append((addr, func_name))

        except Exception as e:
                print(f"[ERROR] Processing error {e}")

    return result

extract_renamed_function()