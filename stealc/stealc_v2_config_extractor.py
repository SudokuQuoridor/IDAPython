# Author: SudokuQuoridor
# Sample: A332B3C53F084CFCA26B0C9D8C09B9B6105D4073

import re
import base64
from dataclasses import dataclass
from typing import Optional, List
import binascii
import argparse
import json

# RC4 복호화 KSA/PRGA 
def rc4_decrypt(encrypted_data: bytes, rc4_decrypt_key: bytes) -> bytes:
	# 인자값 예외 처리
	if not isinstance(encrypted_data, bytes):
		raise TypeError("encrypted_data must be bytes")
	if not rc4_decrypt_key:
		raise ValueError("rc4_decrypt_key must be not empty")

	# KSA
	S = list(range(256))
	j = 0    
	
	key_len = len(rc4_decrypt_key)
	for i in range(256):
		j = (j + S[i] + rc4_decrypt_key[i % key_len]) % 256
		S[i], S[j] = S[j], S[i]
		
	# PRGA
	i = 0
	j = 0
	result = bytearray()
	for byte in encrypted_data:
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]      
         
		k = S[(S[i] + S[j]) % 256]
		result.append(byte ^ k)
		
	return bytes(result)

def find_base64(binary_data: bytes, min_length: int = 8) -> List[bytes]:
	if not isinstance(binary_data, bytes):
		raise TypeError("binary_data must be bytes")
	if not binary_data:
		raise ValueError("binary_data must be not empty")

	result = []
	pattern = re.compile(rb'[A-Za-z0-9+/]{%d,}={0,2}' % min_length)

	for match in pattern.finditer(binary_data):
		base64_bytes = match.group(0)

		# Base64 길이 검증
		if len(base64_bytes) % 4 != 0:
			continue
	
		try:
			base64.b64decode(base64_bytes, validate=True)
			result.append(base64_bytes)

		except (binascii.Error, ValueError):
			continue

	return result

@dataclass
class stealc_config_bytes:
	build_id: bytes
	rc4_trans_key: bytes
	rc4_decrypt_key: bytes
	day: bytes
	month: bytes
	yy1: bytes
	yy2: bytes

@dataclass
class stealc_config_str:
	c2_url: str
	build_id: str
	rc4_trans_key: str
	rc4_decrypt_key: str
	expired_date: str

PRINTABLE_RUN = re.compile(rb'[\x20-\x7E]+')
def extract_printable_run(buf: bytes) -> List[bytes]:
	return [m.group(0) for m in PRINTABLE_RUN.finditer(buf)]

def parse_candidate(run: List[bytes]) -> Optional[stealc_config_bytes]:
	
	if len(run) < 7:
		return None
	
	build_id, trans, decrypt, day, month, yy1, yy2 = run[:7]

	return stealc_config_bytes(build_id, trans, decrypt, day, month, yy1, yy2)

def extract_C2_config(binary: bytes) -> Optional[stealc_config_bytes]:
	opcode = b"string too long"
	pos = 0
	cand = None

	while True:
		pos = binary.find(opcode, pos)

		if pos == -1:
			break

		window = binary[pos + len(opcode): pos + len(opcode) + 0x100]
		run = extract_printable_run(window)

		cand = parse_candidate(run)
		if cand:
			return cand

		pos = pos + 1
	
	return None

BASE64 = re.compile(rb'[a-zA-Z0-9+/]+={0,2}')
def is_base64(b64: bytes) -> bool:
	if not isinstance(b64, bytes):
		raise TypeError("b64 must be bytes")
	if not b64:
		return False

	if BASE64.fullmatch(b64) and len(b64) % 4 == 0:
		try:
			base64.b64decode(b64, validate=True)
			return True
		except (binascii.Error, ValueError):
			return False
		
	return False	

PRINTABLE_ASCII = re.compile(rb'^[\x20-\x7E]+$')
def decrypt_string(base64_encoded: bytes, rc4_decrypt_key: bytes) -> Optional[str]:
	if is_base64(base64_encoded):
		try:
			encrypted = base64.b64decode(base64_encoded, validate=True)

			decrypted_data = rc4_decrypt(encrypted, rc4_decrypt_key)

			if PRINTABLE_ASCII.fullmatch(decrypted_data):
				return decrypted_data.decode("ascii", errors="ignore")
			
		except(binascii.Error, ValueError, TypeError):
			return None
		
	return None

HTTP_IP = re.compile(r'^http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
URL_PATH_PHP = re.compile(r'^/[a-zA-Z0-9/-\_~]+\.php$')

def is_http_domain(string: str) -> bool:
	if re.search(HTTP_IP, string):
		return True
	
	return False

def is_urlpath_php(string: str) -> bool:
	if re.search(URL_PATH_PHP, string):
		return True
	
	return False

def convert_c2_config_to_str(c2_url: str, rc4_key: bytes, config_bytes: stealc_config_bytes) -> Optional[stealc_config_str]:
	try:
		build_id_str = config_bytes.build_id.decode("ascii")
		rc4_trans_key_str = config_bytes.rc4_trans_key.decode("ascii")
		rc4_decrypt_key_str = config_bytes.rc4_decrypt_key.decode("ascii")
	except UnicodeDecodeError:
		print("[ERROR] Failed to convert c2_config str")
		return None

	build_id_str = build_id_str.strip(" ")

	day = decrypt_string(config_bytes.day, rc4_key)
	month = decrypt_string(config_bytes.month, rc4_key)
	yy1 = decrypt_string(config_bytes.yy1, rc4_key)
	yy2 = decrypt_string(config_bytes.yy2, rc4_key)

	if not all([day, month, yy1, yy2]):
		return None

	date_str = f"{yy1}{yy2}/{month}/{day}"
	
	return stealc_config_str(c2_url, build_id_str, rc4_trans_key_str, rc4_decrypt_key_str, date_str)

def main():
	parse = argparse.ArgumentParser(description = "Stealc V2 config Extrator C2 URL, RC4_Trans_key,  RC4_Decrypt_key, Expired Date")
	parse.add_argument("file", help = "Select Unpacked Stealc V2 file")
	parse.add_argument("-min_length", help = "Limit length at Search Base64 Pattern, Default: 8", default = 8, type = int)
	parse.add_argument("-rc4_key", help = "Specify rc4 key for decrpyt", type = str)
	parse.add_argument("-out_file", help = "Specify Result Path", type = str)
	args = parse.parse_args()

	try:
		with open(args.file, 'rb') as r:
			binary = r.read()
	except FileNotFoundError:
		print(f"[ERROR] Failed {args.file} not founded")
		return False

	rc4_key = b''
	base64_list = []
	decrypted_str = ''
	decrypted_list = []
	http_ip = ''
	urlpath_php = ''
	c2_url = ''
	c2_config = extract_C2_config(binary)

	if not c2_config:
		print(f"[INFO] Failed to find opcode, check the opcode string")
		return False

	if args.rc4_key:
		rc4_key = args.rc4_key.encode("utf-8", errors="ignore")
	elif c2_config.rc4_decrypt_key:
		rc4_key = c2_config.rc4_decrypt_key
	else:
		print("[ERROR] Failed to found rc4_key")
		return False

	base64_list = find_base64(binary, args.min_length)

	for b in base64_list:
		decrypted_str = decrypt_string(b, rc4_key)
		if decrypted_str:
			decrypted_list.append(decrypted_str)

	for url in decrypted_list:
		if not(http_ip) and is_http_domain(url):
			http_ip = url
		if not(urlpath_php) and is_urlpath_php(url):
			urlpath_php = url

		if http_ip and urlpath_php:
			break

	if http_ip and urlpath_php:
		c2_url = f"{http_ip}{urlpath_php}"
	else:
		print(f"[ERROR] Failed to found url path {http_ip} {urlpath_php}")
		return False

	c2_config_str = convert_c2_config_to_str(c2_url, rc4_key, c2_config)
	if c2_config_str is None:
		print(f"[ERROR] Failed to Convert c2_config")
		return False
	
	try:
		if args.out_file:
			with open(args.out_file, "w", encoding="utf-8") as o:
				json.dump(c2_config_str.__dict__, o, indent=2)
		else:
			with open("result.json", "w", encoding="utf-8") as o:
				json.dump(c2_config_str.__dict__, o, indent=2)
	except Exception as e:
		print(f"[ERROR] Failed to write result.json {e}")		
		
	print(f"[OK] Success to Extrator Stealc V2 config")

if __name__ == "__main__":
    main()