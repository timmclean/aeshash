#!/usr/bin/env python3

# Performs a chosen-prefix collision attack against aeshash

import aeshash

from Crypto.Cipher import AES

def generateSecondPreimage(msg, newPrefix):
	if len(msg) < len(newPrefix) + aeshash.blockSize:
		raise ValueError('newPrefix is too long relative to msg')

	if len(newPrefix) % aeshash.blockSize:
		raise ValueError('newPrefix must be an integer number of blocks')

	oldPrefix = msg[: len(newPrefix) + aeshash.blockSize]

	oldPrefixHash = aeshash.rawHash(oldPrefix)
	newPrefixHash = aeshash.rawHash(newPrefix)

	collisionBlock = AES.new(newPrefixHash, AES.MODE_ECB).decrypt(oldPrefixHash)

	return newPrefix + collisionBlock + msg[len(newPrefix) + aeshash.blockSize :]

def runTest():
	import binascii
	def hex(x):
		return binascii.hexlify(x).decode('utf8')

	with open('original.txt', 'rb') as f:
		original = f.read()

	with open('new-prefix.txt', 'rb') as f:
		newPrefix = f.read()

	print('forged prefix length: ' + str(len(newPrefix)))

	forged = generateSecondPreimage(original, newPrefix)
	with open('forged.txt', 'wb') as f:
		f.write(forged)

	print('aeshash(original) = ' + hex(aeshash.aeshash(original)))
	print('aeshash(forged)   = ' + hex(aeshash.aeshash(forged)))

if __name__ == '__main__':
	runTest()
