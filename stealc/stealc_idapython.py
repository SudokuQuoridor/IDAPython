##################################################################################
    # 목표: Stealc에서 Base64/RC4 암호화된 문자열 복호화 및 IDA rename 또는 주석
    
    # 모듈(기능)
    # 1. RC4 Key 찾기
    #   ㄱ. 모든 세그먼트 데이터 읽기
    #   ㄴ. opcode(string too long) 이후 세 번째 문자열(RC4 Key) 찾기
    
    # 2. 문자열 찾기
    #   ㄱ. .text 세그먼트 데이터 읽기
    #   ㄴ. lea rdx 명령어 찾기
    #   ㄷ. 첫 번째 operand가 Base64 포멧인지 확인
    
    # 3. RC4 복호화
    #   ㄱ. RC4 알고리즘 구현
    #   > KSA, 
    
    # 4. IDA rename 또는 주석
    #   ㄱ. sanitize 네이밍
    #   ㄴ. IDA rename 또는 주석
    
    # main 함수 흐름
    # 1. RC4 Key 찾기
    #   > find_rc4_key(get_binary_data())
    # 2. 문자열 찾기
    # 3. RC4 복호화
    # 4. IDA rename 또는 주석
##################################################################################

import idautils
import ida_bytes
import ida_segment
import re
import base64
import idc
import string
import ida_name
import ida_idaapi

#RC4 Key 찾기 위해 모든 시그먼트 읽기
def get_binary_data():
    result = bytearray()

    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        seg_start = seg
        seg_end = idc.get_segm_end(seg)
        seg_size = seg_end - seg_start
        
        seg_bytes = ida_bytes.get_bytes(seg_start, seg_size)
        if seg_bytes:
            print(f"[OK] {seg_name} Load Success")
            result.extend(seg_bytes)
        else:
            print(f"[ERROR] {seg_name} Load failed")
            
    return bytes(result)        
    
def find_rc4_key(binary_data):
    #stealc는 string too long ASCII 문자열 뒤 0x00을 구분자로 3번째 뒤에 RC4_key가 존재
    opcode = bytes.fromhex("73 74 72 69 6E 67 20 74 6F 6F 20 6C 6F 6E 67")
    
    positions = []
    pos = binary_data.find(opcode)
    
    if not pos:
        print("[ERROR] can't find opcode")
        return False
    
    while pos != -1:
        positions.append(pos)
        pos = binary_data.find(opcode, pos + 1)
        
    current_str = ""
    count = 0
    build_id = None
    rc4_key = None
    for pos in positions:
        #string too long 문자열 이후 0x40 바이트 이내에 rc4_key가 존재하나 러프하게 0x80(128) 범위로 지정
        structure_bytes = binary_data[pos + len(opcode): pos + len(opcode) + 128]
        
        for b in structure_bytes:
            #printable ASCII 범위가 아닌 경우 count 증가
            if 32 <= b <= 126:
                current_str += chr(b)
            elif current_str:
                count += 1
                
                if count == 1:
                    build_id = current_str
                    
                if count == 3:
                    rc4_key = current_str
                
                current_str = ""
                
        if build_id and rc4_key:
            print(f"[OK] build_id: {build_id} rc4_key: {rc4_key}")
            break
                
    return rc4_key
    
    
#Base64 문자열인지 확인
def is_base64(s):
	pattern = r'^[a-zA-Z0-9+/]+={0,2}$'
	
	if re.match(pattern, s) and len(s) % 4 == 0:
		try:
			base64.b64decode(s)
			return True
		except:
			pass
	return False	
    

#.text 섹션에 lea rdx 명령어에 첫 번째 오퍼랜드 추출    
def find_lea_rdx_instructions():
	result = []
	
	seg = ida_segment.get_segm_by_name(".text")
    
	if not seg:
		print("[ERROR] .text Segment not found")
		return result
		
	current_addr = seg.start_ea
	count = 0
	
	while True:
        # count 변수를 사용하여 첫 번째 실행 시 idc.next_head 함수 건너뛰기
		if count != 0:
			current_addr = idc.next_head(current_addr, seg.end_ea)
		
		count = 1
		if current_addr == ida_idaapi.BADADDR or current_addr >= seg.end_ea:
			break
        # insturction이 "lea"인 경우
		mnem = idc.print_insn_mnem(current_addr)
		if mnem != "lea":
			continue
		
        # op0이 "rdx"인 경우
		op0 = idc.print_operand(current_addr, 0)
		if op0 != "rdx":
			continue
		
        # lea rdx인 경우 op1 주소 및 문자열 데이터를 추출
		op1_addr = idc.get_operand_value(current_addr, 1)
		
		str_contents = ida_bytes.get_strlit_contents(op1_addr, -1 ,0)
		
		if str_contents:
			try:
                #op1 문자열 base64 포멧인 경우 리스트에 추가
				str_contents = str_contents.decode('UTF-8', errors='replace')
				if is_base64(str_contents):
					print(f"0x{current_addr:X}, 0x{op1_addr:X}, {str_contents}")
					result.append((current_addr, op1_addr, str_contents))
			except:
				pass
		
	return result	

# rc4 복호화에는 필요한 요소 복호화 알고리즘, 대상 데이터, 키
def rc4_decrpyt(encrypted_data, rc4_key):
    # 1. S-BOX 초기화
    S = list(range(256))
    
    # 2. KSA -> 암호화 바이트 스트림 생성
    j = 0    
    for i in range(256):
        j = (j + S[i] + rc4_key[i % len(rc4_key)]) % 256
        temp = S[i]
        S[i] = S[j]
        S[j] = temp
        
    # 3. PRGA
    i = 0
    j = 0
    result = bytearray()
    for byte in encrypted_data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        temp = S[i]
        S[i] = S[j]
        S[j] = temp        
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
        
    return result    

# base64/rc4 복호화    
def decrypt_string(base64_encoded, key_str):
    try:
        # rc4 암호화를 위해 byte로 형변환
        key_bytes = key_str.encode('utf-8')
        
        # base64 디코딩
        encrypted_data = base64.b64decode(base64_encoded)

        # rc4 복호화
        decrypted_data = rc4_decrpyt(encrypted_data, key_bytes)
        
        # printable ASCII 및 'TAB', 'LF', 'CR'인지
        is_printable = all(32 <= b <= 126 or b in (9, 10, 13) for b in decrypted_data)
        try:
            if is_printable:
                return decrypted_data.decode('utf-8')
            else:
                return decrypted_data.hex()
        except UnicodeDecodeError:
            return decrypted_data.hex()
    except Exception as e:
        return f"Error: {str(e)}"
            
# IDA 변수명 작성 규칙 적용     
def sanitize_name(name):
    #IDA 허용 변수명
    valid_chars = string.ascii_letters + string.digits + '_'
    
    result = ""
    for c in name:
        if c in valid_chars:
            result += c
        else:
            result += '_'
            
    # 첫번째 변수명이 숫자인 경우 '_' 추가        
    if result and not result[0].isalpha() and result[0] != '_':
        result = '_' + result
    
    if not result:
        result = "re_named"
        
    return result
    
# qword 접두사 문자열 찾기    
def find_qwords(lea_isnt_addr, max_instructions=20):
    qwords = []
    
    current_addr = lea_isnt_addr
    end_addr = current_addr + max_instructions * 16
    
    while current_addr < end_addr:
        current_addr = idc.next_head(current_addr)
        
        if current_addr == ida_idaapi.BADADDR:
            break
            
        if idc.print_insn_mnem(current_addr) == "lea" and idc.print_operand(current_addr, 0) == "rcx":
            op1_str = idc.print_operand(current_addr, 1)
            if op1_str.startswith("qword_"):
                qword_addr = idc.get_operand_value(current_addr, 1)
                qwords.append((current_addr, qword_addr))
                
        if idc.print_insn_mnem(current_addr) in ["ret", "jmp"]:
            break
    
    return qwords
    
        
def main():
    # 1. rc4_key 찾기
    binary_data = get_binary_data()
    rc4_key = find_rc4_key(binary_data)
    
    # 2. 복호화 대상 찾기
    matches = find_lea_rdx_instructions()
    
    str_count = 0
    str_var_count = 0
    qword_count = 0
    
    for inst_addr, str_addr, str_encrypted in matches:
        try:
            # 복호화된 문자열 주석 달기
            decrypted = decrypt_string(str_encrypted, rc4_key)
            
            comment = f"Decrypted: \"{decrypted}\""
            if idc.set_cmt(inst_addr, comment, 0):
                str_count += 1
                print(f"Added Comment at 0x{inst_addr:X}: {comment}")
                
            data_comment = f"Decrypted: \"{decrypted}\""  
            idc.set_cmt(str_addr, data_comment, 0)
            
            # 복호화된 문자열로 변수명 변경
            new_name = sanitize_name(f"str_{decrypted[:20]}")
            if ida_name.set_name(str_addr, new_name, ida_name.SN_CHECK):
                str_var_count += 1
                print(f"Renamed string at 0x{str_addr:X}: {new_name}")
                
            # 복호화된 문자열 중 qword 변수명 변경
            qwords = find_qwords(inst_addr, )
            qword_insn = qwords[0]
            qword_addr = qwords[1]
            new_name = sanitize_name(f"str_{decrypted[:20]}")
            if ida_name.set_name(qword_addr, new_name, ida_name.SN_CHECK):
                qword_count += 1
                print(f"Renamed String at 0x{qword_insn:X}: {new_name}")
        
        except Exception as e:
            print(f"[ERROR] processing string at 0x{str_addr:X}: {e}")
                
    print(f"Added {str_count} decryption comments")
    print(f"Renamed {str_var_count} string variables")
    print(f"Renamed {qword_count} associated qword variables")

if __name__ == "__main__":
    main()