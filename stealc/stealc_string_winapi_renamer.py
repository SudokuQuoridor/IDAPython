##################################################################################################################
	# Author: SudokuQuoridor
	# Sample: A332B3C53F084CFCA26B0C9D8C09B9B6105D4073
		
	# 주요 기능
	# 1. RC4 Key 찾기
	# 2. 암호화된 문자열 찾기
	# 3. API 주소를 참조하는 변수 차지 
	# 4. RC4 복호화
	# 5. IDA rename 또는 주석

	# 주의사항
	# 심볼 정보가 등록되어 있는 경우 오류가 발생할 수 있습니다.

	# 샘플 환경 및 패턴 의존성
	# 1. themida 언패킹 및 x64 아키텍쳐의 Stealc v2
	# 2. RC4 Key 찾는 과정에 "string too long" 문자열에 의존하므로, 키를 찾지 못하는 경우 해당 문자열이 존재하는지 확인 필요
	# 3. 암호화된 문자열의 경우 "lea rdx [전역변수]" 명령어를 찾음
	# 4. winapi 참조 변수의 경우 "cmova rdx [전역변수]" -> call(GetProcaddress) -> "mov [참조변수] rax"
	# 5. wininet.dll 관련 API명이 평문으로 저장되어 있으나 추후 변경시 수정 필요
##################################################################################################################

import idautils
import ida_bytes
import ida_segment
import re
import base64
import idc
import string
import ida_name
import ida_idaapi
import ida_nalt
import traceback
import binascii

IMAGEBASE = ida_nalt.get_imagebase()

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
            print(f"[INFO] {seg_name} Load Success")
            result.extend(seg_bytes)
        else:
            print(f"[WARN] {seg_name} Load failed")
            
    return bytes(result)        
    
def find_rc4_key(binary_data):
    #stealc는 "string too long" ASCII 문자열 뒤 0x00을 구분자로 3번째 문자열에 키가 존재
    opcode = bytes.fromhex("73 74 72 69 6E 67 20 74 6F 6F 20 6C 6F 6E 67")
    
    positions = []
    pos = binary_data.find(opcode)
    
    if pos == -1:
        print("[ERROR] Failed to find opcode")
        return None
    
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
            #printable ASCII 범위가 아닌 경우 count 증가하여 3번째 RC4 키 추출
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
    
    
# Base64 문자열인지 확인
def is_base64(s):
	pattern = r'^[a-zA-Z0-9+/]+={0,2}$'
	
	if re.match(pattern, s) and len(s) % 4 == 0:
		try:
			base64.b64decode(s, validate=True)
			return True
		except (binascii.Error, ValueError):
			return False
		
	return False	

# wininet.dll 관련 API명 예외 처리 -> Stealc는 wininet.dll 관련 API 문자열의 경우 평문으로 존재
def is_wininet(s):
    # wininet API 리스트 총 9개 중 InternetOpenUrlA는 사용 안함 -> 변형 시 리스트 갱신 필요
	wininet = {
		"InternetConnectW",
		"InternetCloseHandle",
		"HttpSendRequestW",
		"InternetReadFile",
		"InternetOpenW",
		"InternetOpenUrlA",
		"HttpOpenRequestW",
		"InternetCrackUrlW",
		"InternetSetOptionA"
	}

	# 리스트 목록에 포함 여부
	return s in wininet

def find_wininet():
	result = []
	max_instructions = 4

	seg = ida_segment.get_segm_by_name(".text")
		
	if not seg:
		print("[ERROR] Failed to find .text Segments")
		return result
		
	ea = seg.start_ea
	end_ea = seg.end_ea
	
	while ea != ida_idaapi.BADADDR and ea < end_ea:
		if idc.print_insn_mnem(ea) == "lea" and idc.print_operand(ea, 0) == "rdx":
			op1_addr = idc.get_operand_value(ea, 1)
			op1_str = ida_bytes.get_strlit_contents(op1_addr, -1, 0)

			if not op1_str:
				ea = idc.next_head(ea)
				continue

			op1_win = op1_str.decode('UTF-8', errors='replace')
			
			if is_wininet(op1_win):
				current_addr = ea
				end_addr = current_addr + max_instructions * 0x10

				call_count = 0
				while current_addr != ida_idaapi.BADADDR and current_addr < end_addr:
					# 첫 번째 call(GetProcAddress) 호출 이후 mov qword rax 패턴 매칭
					if idc.print_insn_mnem(current_addr) == "call":
						call_count += 1
						call_addr = current_addr

					# 두 번쨰 call(GetProcAddress) 호출 되는 경우 사용하지 않지만 삽입한 API 문자열로 Abort
					if call_count == 2:
						break

					if call_count == 1 and current_addr > call_addr:
						if idc.print_insn_mnem(current_addr) == "mov" and idc.print_operand(current_addr, 1) == "rax":
							op0_addr = idc.get_operand_value(current_addr, 0)
							result.append((op0_addr, op1_win))

					current_addr = idc.next_head(current_addr)

		ea = idc.next_head(ea)

	return result



# .text 섹션에 lea rdx 명령어에 첫 번째 오퍼랜드 추출    
def find_lea_rdx_instructions():
	result = []
	
	seg = ida_segment.get_segm_by_name(".text")
    
	if not seg:
		print("[ERROR] Failed to find .text Segments")
		return result
		
	ea = seg.start_ea
	end_ea = seg.end_ea
	
	while ea != ida_idaapi.BADADDR and ea < end_ea:
		# lea rdx 명령어 찾기
		if idc.print_insn_mnem(ea) == "lea" and idc.print_operand(ea, 0) == "rdx":
			op1_addr = idc.get_operand_value(ea, 1)
			str_contents = ida_bytes.get_strlit_contents(op1_addr, -1 ,0)
		
			if str_contents:
				try:
					str_contents = str_contents.decode('UTF-8', errors='replace').rstrip('\x00')

					# wininet API는 평문으로 제외
					if is_wininet(str_contents):
						ea = idc.next_head(ea)
						continue

					# base64 포멧인 경우 리스트에 추가
					if is_base64(str_contents):
						result.append((ea, op1_addr, str_contents))
							
				except Exception as e:
					print(f"[WARN] str decode error at 0x{ea:X}: {e}")

		ea = idc.next_head(ea)
		
	return result	

# rc4 복호화 알고리즘
def rc4_decrypt(encrypted_data, rc4_key):
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
        decrypted_data = rc4_decrypt(encrypted_data, key_bytes)
        
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
		
	MAX_LEN = 64
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
		
	return result[:MAX_LEN]

# IDA 자동 심볼링으로 인한 주소 기반 qword 찾기
def is_qword(qword_addr):

	if qword_addr < IMAGEBASE:
		return False
	
	flags = ida_bytes.get_full_flags(qword_addr)
	if not ida_bytes.is_data(flags):
		return False
	
	return ida_bytes.get_item_size(qword_addr) == 8

# qword 접두사 문자열 찾기    
def find_qwords(lea_inst_addr, max_instructions=20):
	qwords = []
	
	current_addr = lea_inst_addr
	end_addr = current_addr + max_instructions * 16
	
	while current_addr < end_addr:
		current_addr = idc.next_head(current_addr)
		
		if current_addr == ida_idaapi.BADADDR:
			break
			
		if idc.print_insn_mnem(current_addr) == "lea" and idc.print_operand(current_addr, 0) == "rcx":
			
			if idc.get_operand_type(current_addr, 1) == idc.o_mem:
				name_slot_addr = idc.get_operand_value(current_addr, 1)
				if is_qword(name_slot_addr):
					qwords.append((current_addr, name_slot_addr))
				
		if idc.print_insn_mnem(current_addr) in ["ret", "jmp"]:
			break
	
	return qwords

# WinAPI move cs:qword[주소] rax 명령어 찾기
def find_winapi(max_instructions=5):
	result = {}

	# .text 섹션 로드
	text = ida_segment.get_segm_by_name(".text")

	if not text:
		print("[ERROR] failded to load .text Segment")
		return result

	ea = text.start_ea
	end_ea = text.end_ea

	# .text 섹션 범위 명령어 탐색
	while ea != ida_idaapi.BADADDR and ea < end_ea:
		# comva rdx 명령어 찾기 -> lea rdx 도 상관없음
		if idc.print_insn_mnem(ea) == "cmova" and idc.print_operand(ea, 0) == "rdx":
			name_slot_addr = idc.get_operand_value(ea, 1)
			# 첫 번째 operand  = 0, (operand + 0x18) = 0xF 인 경우
			if ida_bytes.get_qword(name_slot_addr) == 0 and ida_bytes.get_qword(name_slot_addr + 0x18) == 0xF:
				current_addr = ea
				end_addr = ea + max_instructions * 0x10
				call_count = 0

				call_addr = ida_idaapi.BADADDR
				while current_addr != ida_idaapi.BADADDR and current_addr < end_addr:
					# mnem == call(GetProcAddress) 찾기
					if idc.print_insn_mnem(current_addr) == "call":
						call_addr = current_addr
						call_count += 1

					# call(GetProcAddress) 두 번째 호출 시 탐색 중단
					if call_count == 2:
						break

					if call_addr != ida_idaapi.BADADDR and call_addr < current_addr:
						if idc.print_insn_mnem(current_addr) == "mov" and idc.print_operand(current_addr, 1) == "rax":
							winapi_addr = idc.get_operand_value(current_addr, 0)
							# 문자열 참조 변수, WinAPI 참조 변수 추가

							# winapi 참조 변수가 0x140000000(imagebase) 보다 큰 주소인 경우
							if winapi_addr >= IMAGEBASE:
								result[name_slot_addr] = (winapi_addr)

					current_addr = idc.next_head(current_addr)						

		ea = idc.next_head(ea)			

	return result	
    
        
def main():
	# 1. rc4_key 찾기
	binary_data = get_binary_data()
	rc4_key = find_rc4_key(binary_data)
	if not rc4_key:
		print("[ERROR] Failed to find RC4 Key")
		return
	
	# 2. 복호화 대상 찾기

	matches = find_lea_rdx_instructions()

	dict_winapi = find_winapi()   
			
	str_count = 0
	str_var_count = 0
	wininet_count = 0
	qword_count = 0
	winapi_count = 0

	wininet_list = find_wininet()
	# wininet.dll 관련 심볼 등록
	for wininet_addr, wininet_str in wininet_list:
		wininet_api_name = sanitize_name(f"api_{wininet_str[:20]}")
		if ida_name.set_name(wininet_addr, wininet_api_name, ida_name.SN_CHECK):
			wininet_count += 1
			print(f"[INFO] Reanemd wininet String at 0x{wininet_addr:X}: {wininet_api_name}")

	for inst_addr, str_addr, str_encrypted in matches:
		try:
			# 복호화된 문자열 주석 달기
			decrypted = decrypt_string(str_encrypted, rc4_key)

			if decrypted is None:
				continue

			comment = f"Decrypted: \"{decrypted}\""
			if idc.set_cmt(inst_addr, comment, 0):
				str_count += 1
				print(f"[INFO] Added Comment at 0x{inst_addr:X}: {comment}")
				
			data_comment = f"Decrypted: \"{decrypted}\""  
			idc.set_cmt(str_addr, data_comment, 0)
			
			# 복호화된 문자열로 변수명 변경
			new_name = sanitize_name(f"str_{decrypted[:20]}")
			if ida_name.set_name(str_addr, new_name, ida_name.SN_CHECK):
				str_var_count += 1
				print(f"[INFO] Renamed string at 0x{str_addr:X}: {new_name}")      
                              
			# WinAPI 문자열 심볼 등록
			assoicated_qwords = find_qwords(inst_addr)
			for qword_inst_addr, name_slot_addr in assoicated_qwords:
				winapi_addr = dict_winapi.get(name_slot_addr)
				if winapi_addr:
					api_new_name = sanitize_name(f"api_{decrypted[:20]}")
					if ida_name.set_name(winapi_addr, api_new_name, ida_name.SN_CHECK):
						winapi_count += 1
						print(f"[INFO] Renamed winapi String at 0x{winapi_addr:X}: {api_new_name}")
                                    
			# 복호화된 문자열 중 qword 변수명 변경
			for qword_inst_addr, name_slot_addr in assoicated_qwords:
				qword_new_name = sanitize_name(f"qw_{decrypted[:20]}")
				if ida_name.set_name(name_slot_addr, qword_new_name, ida_name.SN_CHECK):
					qword_count += 1
					print(f"[INFO] Renamed String at 0x{name_slot_addr:X}: {qword_new_name}")     
                                             
		except Exception as e:
			print(f"[ERROR] processing string at 0x{str_addr:X}: {e}")
			traceback.print_exc()
                  
	# 최종 결과 출력            
	print(f"Added {str_count} decryption comments")
	print(f"Renamed {str_var_count} string variables")
	print(f"Renamed {qword_count} associated qword variables")
	print(f"Renamed {winapi_count} associated winapi variables")
	print(f"Renamed {wininet_count} associated wininet variables")    	

if __name__ == "__main__":
    main()