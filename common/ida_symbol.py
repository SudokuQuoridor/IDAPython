import idc

# WinAPI 파일 경로
file_path = r"C:\Users\amdin\Desktop\S2W\unlicense-py3.11-x64\api4.txt"

try:
    with open(file_path, "r") as f:
        lines = f.readlines()
except Exception as e:
    print(f"[Error] 파일을 열 수 없습니다: {e}")
    lines = []

for line in lines:
    line = line.strip()
    if not line:
        continue

    parts = line.split(None, 1)
    if len(parts) != 2:
        print(f"[Skip] 잘못된 형식: {line}")
        continue

    va_str, func_name = parts

    # VA 문자열을 16진수 정수로 변환
    try:
        if va_str.lower().startswith("0x"):
            va = int(va_str, 16)
        else:
            va = int(va_str, 16)
    except Exception as e:
        print(f"[Skip] VA 변환 실패: {va_str} ({e})")
        continue

    # 함수 시그니처 등록 시도 (실패해도 무시)
    idc.add_func(va)

    # 1차 시도: 원본 함수명
    if idc.set_name(va, func_name, idc.SN_CHECK):
        print(f"[OK] {func_name} -> {hex(va)}")
        continue

    # 2차 시도: __접두사 붙인 이름
    alt_name = "__" + func_name
    if idc.set_name(va, alt_name, idc.SN_CHECK):
        print(f"[OK] (ALT) {alt_name} -> {hex(va)}")
        continue

    # 모두 실패하면
    print(f"[Fail] {func_name} -> {hex(va)}")

print("심볼 등록 완료!")
