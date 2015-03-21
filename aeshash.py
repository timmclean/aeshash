# Implements a broken hashing scheme based on AES

import struct

from Crypto.Cipher import AES

blockSize = 16 # 128 bits, matches AES
iv = b'\xFF' * blockSize
paddingStartByte = b'\x80' # a one-bit followed by 7 zero-bits

def aeshash(msg):
	return rawHash(pad(msg))

def rawHash(paddedMsg):
	state = iv

	for pos in range(0, len(paddedMsg), blockSize):
		block = paddedMsg[pos:pos+blockSize]
		state = compress(state, block)

	return state

def pad(msg):
	result = msg

	result += paddingStartByte
	result += b'\0' * ((blockSize - len(msg) - 1 - 8) % blockSize)
	result += encodeUInt64(len(msg))

	return result

def encodeUInt64(n):
	return struct.pack('<Q', n)

def compress(state, nextBlock):
	return AES.new(state, AES.MODE_ECB).encrypt(nextBlock)

def runTest():
	import binascii
	def hex(x):
		return binascii.hexlify(x).decode('utf8')

	msg = b'1234567890'*2
	print(hex(pad(msg)))
	print(hex(hash(msg)))

if __name__ == '__main__':
	runTest()
