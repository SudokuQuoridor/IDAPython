# Author: SudokuQuoridor
# vidar 2.0 17.1 UPX unpacked SHA1: 292E9BA6755EDF4DAC79921E020E23DCF408FBA9

# Anchor Pattern 
# 1. mov reg8 [src_base(reg/stack) + idx(reg)]
# 2. xor reg8 imm8
# 3. mov [dst_base(reg) + idx(reg)] reg8

import ida_funcs
import idaapi
import idc
import ida_bytes
import idautils
import ida_name
import re
import traceback
import string
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass
class Anchor:
	load_str_ea: int
	xor_reg_ea: int
	store_str_ea: int
	idx: str
	key: int
	src_base: str
	dst_base: str

MEM_RE = re.compile(r"\[([^\]]+)\]")
def parse_base_and_idx(operand: str) -> Tuple[Optional[str], Optional[str]]:
	m = MEM_RE.search(operand.replace(" ", ""))

	if not m:
		return (None, None)
	
	base_idx = re.split(r"[\+\-]", m.group(1))

	regs = [reg.lower() for reg in base_idx if re.fullmatch(r"r\d{1,2}b?|[a-d]l|[a-d]h|rbp|rsp|rcx|rdx|rsi|rdi|rax|rbx|r8|r9|r10|r11|r12|r13|r14|r15", reg.lower())] 

	if len(regs) >= 2:
		return (regs[0], regs[1])
	else:
		return (None, None)

def collect_anchors_in_func(func_ea: int) -> List[Anchor]:
	anchors = []
	f = ida_funcs.get_func(func_ea)

	if not f:
		return anchors
	
	ea = f.start_ea
	while ea != idaapi.BADADDR and ea < f.end_ea:
		# 1. mov reg8 [src_base(reg/stack) + idx(reg)]
		if idc.print_insn_mnem(ea).lower() == "mov":

			insn1 = idaapi.insn_t()

			if idaapi.decode_insn(insn1, ea) == 0:
				ea = idc.next_head(ea, f.end_ea); continue
			
			if not insn1.ops[0].type == idaapi.o_reg:
				ea = idc.next_head(ea, f.end_ea); continue

			reg8 = idc.print_operand(ea, 0).lower()
			
			if not reg8:
				ea = idc.next_head(ea, f.end_ea); continue
			
			if not (reg8.endswith("b") or reg8 in("al", "bl", "cl", "dl")):
				ea = idc.next_head(ea, f.end_ea); continue
			
			op1 = idc.print_operand(ea, 1).lower()

			if '[' not in op1:
				ea = idc.next_head(ea, f.end_ea); continue
			
			# 2. xor reg8 imm8
			ea2 = idc.next_head(ea, f.end_ea)
			if idc.print_insn_mnem(ea2).lower() != "xor":
				ea = idc.next_head(ea, f.end_ea); continue

			insn2 = idaapi.insn_t()

			if idaapi.decode_insn(insn2, ea2) == 0:
				ea = idc.next_head(ea, f.end_ea); continue

			if insn2.ops[0].type != idaapi.o_reg:
				ea = idc.next_head(ea, f.end_ea); continue

			reg2 = idc.print_operand(ea2, 0).lower()

			if reg2 != reg8:
				ea = idc.next_head(ea, f.end_ea); continue

			if not (insn2.ops[1].type == idaapi.o_imm and 0x00 <= insn2.ops[1].value <= 0xFF):
				ea = idc.next_head(ea, f.end_ea); continue

			key = insn2.ops[1].value & 0xFF
			
			# 3. mov [dst_base(reg) + idx(reg)] reg8
			ea3 = idc.next_head(ea2, f.end_ea)
			if idc.print_insn_mnem(ea3).lower() != "mov":
				ea = idc.next_head(ea, f.end_ea); continue
			
			insn3 = idaapi.insn_t()

			if idaapi.decode_insn(insn3, ea3) == 0:
				ea = idc.next_head(ea, f.end_ea); continue
			
			if insn3.ops[1].type != idaapi.o_reg:
				ea = idc.next_head(ea, f.end_ea); continue

			reg3 = idc.print_operand(ea3, 1).lower()
			
			if reg3 != reg8:
				ea = idc.next_head(ea, f.end_ea); continue
			
			op0 = idc.print_operand(ea3, 0)

			if '[' not in op0:
				ea = idc.next_head(ea, f.end_ea); continue
			
			# Choose idx reg
			src_base, src_idx = parse_base_and_idx(op1)
			dst_base, dst_idx = parse_base_and_idx(op0)

			idx = None
			src_set = set([r for r in (src_base, src_idx) if r])
			dst_set = set([r for r in (dst_base, dst_idx) if r])
			inter = src_set.intersection(dst_set)
			idx = next(iter(inter), None)

			if not (idx and src_base and src_idx and dst_base and dst_idx):
				ea = idc.next_head(ea, f.end_ea); continue
			
			if src_base == idx and src_idx and src_idx != idx:
				src_base = src_idx
			if dst_base == idx and dst_idx and dst_idx != idx:
				dst_base = dst_idx

			anchors.append(Anchor(
				load_str_ea= ea,
				xor_reg_ea= ea2,
				store_str_ea= ea3,
				idx= idx,
				key= key,
				src_base= src_base,
				dst_base= dst_base
			))

			ea = idc.next_head(ea3, f.end_ea); continue

		ea = idc.next_head(ea, f.end_ea)

	return anchors

def find_string_len(idx: str, anchor_ea: int, max_forward_insn: int = 17, max_backward_insn: int = 20) -> Optional[int]:
	f = ida_funcs.get_func(anchor_ea)

	if not f:
		return None
	
	# search backward pattern: cmp idx(reg) imm8
	ea = anchor_ea
	for _ in range(max_backward_insn):
		ea = idc.prev_head(ea, f.start_ea)

		if ea == idaapi.BADADDR or ea < f.start_ea:
			break

		if idc.print_insn_mnem(ea).lower() != "cmp":
			continue

		insn = idaapi.insn_t()

		if idaapi.decode_insn(insn, ea) == 0:
			continue

		if insn.ops[0].type != idaapi.o_reg or insn.ops[1].type != idaapi.o_imm:
			continue

		reg = idc.print_operand(ea, 0).lower()

		if reg != idx:
			continue

		if not (0x01 <= insn.ops[1].value <= 0xFF):
			continue

		return insn.ops[1].value

	# search forward
	ea = anchor_ea
	for _ in range(max_forward_insn):
		ea = idc.next_head(ea, f.end_ea)

		if ea == idaapi.BADADDR or ea > f.end_ea:
			break

		if idc.print_insn_mnem(ea).lower() != "cmp":
			continue
		
		insn = idaapi.insn_t()
		if idaapi.decode_insn(insn, ea) == 0:
			continue
		
		if insn.ops[0].type != idaapi.o_reg or insn.ops[1].type != idaapi.o_imm:
			continue

		reg = idc.print_operand(ea, 0).lower()

		if reg != idx:
			continue
		
		if not (0x01 <= insn.ops[1].value <= 0xFF):
			continue
		
		return insn.ops[1].value

	return None

# movups  xmm9, cs:xmmword_7FF7376A34E8
def find_encrypted_bytes(anchor_ea: int, max_backward_insn: int = 0x100) -> Optional[bytes]:
	f = ida_funcs.get_func(anchor_ea)
	encrypted_addrs = []
	encrypted_bytes = bytearray()

	if not f:
		return None
	
	count = 0
	ea = anchor_ea
	for _ in range(max_backward_insn):
		ea = idc.prev_head(ea, f.start_ea)

		if ea == idaapi.BADADDR or ea < f.start_ea:
			break
		
		if idc.print_insn_mnem(ea).lower() != "movups":
			continue

		insn = idaapi.insn_t()

		if idaapi.decode_insn(insn, ea) == 0:
			continue

		if insn.ops[0].type != idaapi.o_reg or insn.ops[1].type != idaapi.o_mem:
			continue
		
		if count < 4:
			encrypted_addrs.append(insn.ops[1].addr)
			count += 1
		else:
			break

	if len(encrypted_addrs) != 4:
		print(f"[ERROR] Failed to collect encrypted string anchor_ea{anchor_ea:X}")
		return None
	
	# 순서 정렬 필요
	encrypted_addrs.sort()

	for addr in encrypted_addrs:
		blob = ida_bytes.get_bytes(addr, 0x10)
		encrypted_bytes.extend(blob)
			
	return bytes(encrypted_bytes)

def find_rename_addr(anchor_ea: int, dst_base: str, max_backward_insn = 80) -> Optional[int]:
	f = ida_funcs.get_func(anchor_ea)

	if not f:
		return None
	
	ea = anchor_ea

	for _ in range(max_backward_insn):
		ea = idc.prev_head(ea, f.start_ea)

		if ea == idaapi.BADADDR or ea < f.start_ea:
			break

		if idc.print_insn_mnem(ea).lower() != "lea":
			continue

		insn = idaapi.insn_t()

		if idaapi.decode_insn(insn, ea) == 0:
			continue
		
		if insn.ops[0].type != idaapi.o_reg or insn.ops[1].type != idaapi.o_mem:
			continue

		if idc.print_operand(ea, 0).lower() != dst_base:
			continue

		return insn.ops[1].addr
	
	return None

def xor_decrypted_str(encrypted_bytes: bytes, key: int, length: int) -> Optional[str]:
	decrypted_bytes = bytearray()
	
	if len(encrypted_bytes) < length:
		return None
	
	for i in range(length):
		decrypted_bytes.append(encrypted_bytes[i] ^ key)

	try:
		decrypted_str = decrypted_bytes.decode("ascii", errors="strict")
		return decrypted_str
	except Exception:
		traceback.print_exc()
		return None

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

def add_comment(rename_addr: int, decrypted_str: str) -> bool:
	cmt = f's_"{decrypted_str}"'
	ok = idc.set_cmt(rename_addr, cmt, 1) # repeatable
	
	return bool(ok)

def apply_rename(rename_addr: int, decrypted_str: str) -> bool:
	san_name = sanitize_name(decrypted_str)
	ok = idc.set_name(rename_addr, san_name, ida_name.SN_CHECK)

	return bool(ok)

# Anchor 1개 처리
def process_anchor_in_func(func_ea: int, anc: Anchor) -> Tuple[bool, str]:

	# 1. cmp idx length
	length = find_string_len(anc.idx, anc.load_str_ea)
	if length is None:
		return (False, "[ERROR] Failed to find length")
	
	# 2) movups xmm[0-15] o_mem 
	encrypted_bytes = find_encrypted_bytes(anc.load_str_ea)
	if not encrypted_bytes:
		return (False, "[ERROR] Failed to find encrypted bytes")
	
	# 3. lea dst_base o_mem
	rename_addr = find_rename_addr(anc.load_str_ea, anc.dst_base)
	if rename_addr is None:
		return (False, "[ERROR] Failed to find rename addr")

	# 4) decrypt
	decrypted_str = xor_decrypted_str(encrypted_bytes, anc.key, length)
	if decrypted_str is None:
		return (False, "[ERROR] Failed to decrypt bytes")
	
	# 5) comment
	ok = add_comment(rename_addr, decrypted_str)
	if ok is False:
		return (False, f"[ERROR] Failed to add comment at 0x{rename_addr:X}")
	
	# 6) rename
	ok = apply_rename(rename_addr, decrypted_str)
	if ok is False:
		return (False, f"[ERROR] Failed to apply rename at 0x{rename_addr:X}")
	return (True, decrypted_str)

# 전체 함수 순회 main
def run_all_functions():
	total_funcs = 0
	total_anchors = 0
	ok_cnt = 0
	fail_cnt = 0
	# 실패 사유 통계
	fail_reason: dict[str, int] = {}

	with open("result.txt", "a", encoding="utf-8") as f:
		for func_ea in idautils.Functions():
			total_funcs += 1

			try:
				anchors = collect_anchors_in_func(func_ea)

				if len(anchors) == 0:
					print(f"[ERROR] Failed to find anchor in func at 0x{func_ea:X}")
					continue

				total_anchors += len(anchors)

				for anc in anchors:
					ok, info = process_anchor_in_func(func_ea, anc)

					if ok:
						ok_cnt += 1

					else:
						fail_cnt += 1
						fail_reason[info] = fail_reason.get(info, 0) + 1
					
			except Exception:
				fail_cnt += 1
				fail_reason["exception"] = fail_reason.get("exception", 0) + 1
				traceback.print_exc()

	# 최종 요약 출력
	print("========== Vidar XOR Deobfuscation Summary ==========")
	print(f"Total functions scanned : {total_funcs}")
	print(f"Total anchors found     : {total_anchors}")
	print(f"Success(rename+comment) : {ok_cnt}")
	print(f"Failed                 : {fail_cnt}")
	print("-----------------------------------------------------")
	if fail_reason:
		print("[Failure reasons]")
		for k, v in sorted(fail_reason.items(), key=lambda x: x[1], reverse=True):
			print(f"  - {k}: {v}")
	print("-----------------------------------------------------")

if __name__ == "__main__":
	run_all_functions()